

import io.github.novacrypto.toruntime.CheckedExceptionToRuntime;
import org.apache.commons.codec.binary.*;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip39.SeedCalculator;
import io.github.novacrypto.bip44.AddressIndex;
import io.github.novacrypto.bip44.BIP44;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;

import static io.github.novacrypto.toruntime.CheckedExceptionToRuntime.toRuntime;


public class Main {

    private static final String[] dict =
            {"0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000",
                    "1001", "1010", "1011", "1100", "1101", "1110", "1111"};

    private static String[] wordlist = new String[2048];
    private static GenerateKeyStore ks = new GenerateKeyStore();
    private static String password = "password";

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String entropy = createEntropy();
        String mnemonic = generateMnemonic(entropy);
        System.out.println(mnemonic);
        List<String> params = generateKeyPairs(mnemonic);
        genKeyStore(params.get(0), params.get(2), password);
    }

    public static String createEntropy() {
        UUID uuid = UUID.randomUUID();
        String[] digits = uuid.toString().split("\\-");
        StringBuilder randomDigits = new StringBuilder();
        for (String digit : digits) {
            randomDigits.append(digit);
        }
        return randomDigits.toString();
    }

    public static String generateMnemonic(String entropy) {
        System.out.println(entropy);

        //generate sha-256 from entropy
        MessageDigest messageDigest;
        String encodeStr = "";
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest(entropy.getBytes("UTF-8"));
            encodeStr = String.valueOf(Hex.encodeHex(hash));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        System.out.println(encodeStr);
        char firstSHA = encodeStr.charAt(0);
        String new_entropy = entropy + firstSHA;
        String bin_entropy = "";
        for (int i = 0; i < new_entropy.length(); i++) {
            bin_entropy += dict[Integer.parseInt(new_entropy.substring(i, i + 1), 16)];
        }
        System.out.println(bin_entropy);
        String[] segments = new String[12];
        //hardcode
        for (int i = 0; i <= 11; i++) {
            segments[i] = bin_entropy.substring(i * 11, (i + 1) * 11);
        }

        //请修改文件的绝对路径
        String path = "/Users/terry/Documents/GitHub/my/BitcoinDemo/src/main/java/english";
        readTextFile(path);
        String mnemonic = "";

        //generate mnemonic
        mnemonic += wordlist[Integer.valueOf(segments[0], 2)];
        for (int j = 1; j < segments.length; j++) {
            mnemonic += " " + (wordlist[Integer.valueOf(segments[j], 2)]);
        }
        return mnemonic;
    }


    public static void readTextFile(String filePath) {
        try {
            String encoding = "utf-8";
            File file = new File(filePath);
            if (file.isFile() && file.exists()) { //判断文件是否存在
                InputStreamReader read = new InputStreamReader(
                        new FileInputStream(file), encoding);//考虑到编码格式
                BufferedReader bufferedReader = new BufferedReader(read);
                String lineTxt = null;
                int index = 0;
                while ((lineTxt = bufferedReader.readLine()) != null) {
                    wordlist[index++] = lineTxt;
                }
                read.close();
            } else {
                System.out.println("找不到指定的文件");
            }
        } catch (Exception e) {
            System.out.println("读取文件内容出错");
            e.printStackTrace();
        }
    }

    private static List<String> generateKeyPairs(String mnemonic) throws InvalidKeySpecException, NoSuchAlgorithmException {

        // 1. we just need eth wallet for now
        AddressIndex addressIndex = BIP44.m().purpose44().coinType(60).account(0).external().address(0);
        // 2. calculate seed from mnemonics , then get master/root key ; Note that the bip39 passphrase we set "" for common
        String seed;
        String salt = "mnemonic";
        seed = getSeed(mnemonic, salt);
        System.out.println(seed);


        ExtendedPrivateKey rootKey = ExtendedPrivateKey.fromSeed(fromHex(seed), Bitcoin.MAIN_NET);
        // 3. get child private key deriving from master/root key
        ExtendedPrivateKey childPrivateKey = rootKey.derive(addressIndex, AddressIndex.DERIVATION);

        // 4. get key pair
        byte[] privateKeyBytes = childPrivateKey.getKey(); //child private key
        ECKeyPair keyPair = ECKeyPair.create(privateKeyBytes);

        // we 've gotten what we need
        String privateKey = childPrivateKey.getPrivateKey();
        String publicKey = childPrivateKey.neuter().getPublicKey();
        String address = Keys.getAddress(keyPair);
        List<String> returnList = new ArrayList<>();

        System.out.println("privateKey:" + privateKey);
        System.out.println("publicKey:" + publicKey);
        System.out.println("address:" + address);
        returnList.add(privateKey);
        returnList.add(publicKey);
        returnList.add(address);
        return returnList;
    }


    public static String getSeed(String mnemonic, String salt) throws NoSuchAlgorithmException,
            InvalidKeySpecException {

        char[] chars = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD).toCharArray();
        byte[] salt_ = getUtf8Bytes(salt);
        KeySpec spec = new PBEKeySpec(chars, salt_, 2048, 512);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        return String.valueOf(Hex.encodeHex(f.generateSecret(spec).getEncoded()));
    }

    private static byte[] fromHex(String hex) {
        byte[] binary = new byte[hex.length() / 2];
        for (int i = 0; i < binary.length; i++) {
            binary[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return binary;

    }

    private static byte[] getUtf8Bytes(final String string) {
        return toRuntime(new CheckedExceptionToRuntime.Func<byte[]>() {
            @Override
            public byte[] run() throws Exception {
                return string.getBytes("UTF-8");
            }
        });
    }

    private static void genKeyStore(String privateKey, String address, String password){
        ks.genkey(address, password);
        try {
            Thread.sleep(1000); //1000 毫秒，也就是1秒.
        } catch(InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
        ks.protectPrivateKey(privateKey, password);
        ks.getPrivateKey(password);
    }
}


