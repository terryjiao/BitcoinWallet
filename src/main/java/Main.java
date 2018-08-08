

import io.github.novacrypto.base58.Base58;
import io.github.novacrypto.hashing.Sha256;
import io.github.novacrypto.toruntime.CheckedExceptionToRuntime;
import org.apache.commons.codec.binary.*;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.Normalizer;
import java.util.*;

import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip44.AddressIndex;
import io.github.novacrypto.bip44.BIP44;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.web3j.crypto.*;

import static io.github.novacrypto.toruntime.CheckedExceptionToRuntime.toRuntime;


public class Main {

    private static final String[] dict =
            {"0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000",
                    "1001", "1010", "1011", "1100", "1101", "1110", "1111"};

    private static String[] wordlist = new String[2048];
    private static GenerateKeyStore ks = new GenerateKeyStore();
    private static String password = "password";
    private static WalletFile walletFile;

    public static void main(String[] args) throws Exception {
        String entropy = createEntropy();
        String mnemonic = generateMnemonic(entropy);
        System.out.println(mnemonic);
        List<String> params = generateKeyPairs(mnemonic);
        //genKeyStoreByPrivateKey(params.get(0), params.get(2), password);
        try {
            Thread.sleep(1000); //1000 ms
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
        //genKeyStoreByMnemonic(mnemonic, params.get(2), password);
        new SendTransaction().getBalance("0x915489e6a7caf14afc874d678879f18fd0e3a684");
        new SendTransaction().getBalance("0x26857844be5fea27bd48aedced42bb8727501779");
        BigDecimal amount = BigDecimal.valueOf(0.01);
        sendTransaction("0x" + params.get(2), "0x26857844be5fea27bd48aedced42bb8727501779", amount, password, walletFile);
        new SendTransaction().getBalance("0x915489e6a7caf14afc874d678879f18fd0e3a684");
        new SendTransaction().getBalance("0x26857844be5fea27bd48aedced42bb8727501779");
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
        String encodeStr = "";

        byte[] hash = Sha256.sha256(hexStringToByteArray(entropy));
        encodeStr = String.valueOf(Hex.encodeHex(hash));
        System.out.println(encodeStr);
        char firstSHA = encodeStr.charAt(0);
        String new_entropy = entropy + firstSHA;
        String bin_entropy = "";
        for (int i = 0; i < new_entropy.length(); i++) {
            bin_entropy += dict[Integer.parseInt(new_entropy.substring(i, i + 1), 16)];
        }
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

    private static List<String> generateKeyPairs(String mnemonic) throws InvalidKeySpecException, NoSuchAlgorithmException, CipherException {

        // 1. we just need eth wallet for now
        AddressIndex ethAddressIndex = BIP44.m().purpose44().coinType(60).account(0).external().address(0);
        AddressIndex btcAddressIndex = BIP44.m().purpose44().coinType(0).account(0).external().address(0);
        // 2. calculate seed from mnemonics , then get master/root key ; Note that the bip39 passphrase we set "" for common
        String seed;
        String salt = "mnemonic";
        seed = getSeed("head budget daring umbrella misery monkey surge protect toy awesome output elbow", salt);
        System.out.println(seed);


        ExtendedPrivateKey rootKey = ExtendedPrivateKey.fromSeed(hexStringToByteArray(seed), Bitcoin.MAIN_NET);
        // 3. get child private key deriving from master/root key
        ExtendedPrivateKey childPrivateKey = rootKey.derive(ethAddressIndex, AddressIndex.DERIVATION);

        // 4. get key pair
        byte[] privateKeyBytes = childPrivateKey.getKey(); //child private key
        ECKeyPair keyPair = ECKeyPair.create(privateKeyBytes);
        walletFile = Wallet.createLight(password, keyPair);
        List<String> returnList = EthAddress(childPrivateKey, keyPair);

        childPrivateKey = rootKey.derive(btcAddressIndex, AddressIndex.DERIVATION);
        bitcoinAddress(childPrivateKey);

        return returnList;

    }


    /**
     * generate ETH privatekey, publickey and address.
     *
     * @param childPrivateKey
     * @param keyPair
     */
    private static List<String> EthAddress(ExtendedPrivateKey childPrivateKey, ECKeyPair keyPair) {
        String privateKey = childPrivateKey.getPrivateKey();
        String publicKey = childPrivateKey.neuter().getPublicKey();
        String address = Keys.getAddress(keyPair);

        System.out.println("ETH privateKey:" + privateKey);
        System.out.println("ETH publicKey:" + publicKey);
        System.out.println("ETH address:" + address);

        List<String> returnList = new ArrayList<>();
        returnList.add(privateKey);
        returnList.add(publicKey);
        returnList.add(address);
        return returnList;
    }

    /**
     * generate bitcoin privatekey, publickey and address.
     *
     * @param childPrivateKey
     */
    private static void bitcoinAddress(ExtendedPrivateKey childPrivateKey) {
        // 获取比特币私钥
        String privateKey = childPrivateKey.getPrivateKey();
        // 加80前缀和01后缀
        String rk = "80" + privateKey + "01";
        // 生成校验和
        byte[] checksum = Sha256.sha256(hexStringToByteArray(rk));
        checksum = Sha256.sha256(checksum);
        // 取校验和前4位（32bits）
        String end = String.valueOf(Hex.encodeHex(checksum)).substring(0, 8);
        rk = rk + end;
        // 进行base58编码
        String privateK = Base58.base58Encode(hexStringToByteArray(rk));


        // 获取比特币公钥
        String publicKey = childPrivateKey.neuter().getPublicKey();
        // 对公钥进行一次sha256
        byte[] pk256 = hexStringToByteArray(publicKey);
        pk256 = Sha256.sha256(pk256);
        // 进行ripe160加密（20位）
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(pk256, 0, pk256.length);
        byte[] ripemd160Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(ripemd160Bytes, 0);
        // 加00前缀（比特币主网）变成21位
        byte[] extendedRipemd160Bytes = hexStringToByteArray("00" + String.valueOf(Hex.encodeHex(ripemd160Bytes)));
        // 计算校验和
        checksum = Sha256.sha256(extendedRipemd160Bytes);
        checksum = Sha256.sha256(checksum);
        // 加校验和前4位，变成25位
        String pk = String.valueOf(Hex.encodeHex(extendedRipemd160Bytes)) + String.valueOf(Hex.encodeHex(checksum)).substring(0, 8);
        // base58加密
        String address = Base58.base58Encode(hexStringToByteArray(pk));

        System.out.println("bitcoin privateKey:" + privateK);
        System.out.println("bitcoin publicKey:" + publicKey);
        System.out.println("bitcoin address:" + address);

        generateSegwitAddress(address);
    }

    public static String getSeed(String mnemonic, String salt) throws NoSuchAlgorithmException,
            InvalidKeySpecException {

        char[] chars = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD).toCharArray();
        byte[] salt_ = getUtf8Bytes(salt);
        KeySpec spec = new PBEKeySpec(chars, salt_, 2048, 512);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        return String.valueOf(Hex.encodeHex(f.generateSecret(spec).getEncoded()));
    }

    private static void generateSegwitAddress(String address) {
        byte[] decoded = Utils.parseAsHexOrBase58(address);
        // We should throw off header byte that is 0 for Bitcoin (Main)
        byte[] pureBytes = new byte[20];
        System.arraycopy(decoded, 1, pureBytes, 0, 20);
        // Than we should prepend the following bytes:
        byte[] scriptSig = new byte[pureBytes.length + 2];
        scriptSig[0] = 0x00;
        scriptSig[1] = 0x14;
        System.arraycopy(pureBytes, 0, scriptSig, 2, pureBytes.length);
        byte[] addressBytes = org.bitcoinj.core.Utils.sha256hash160(scriptSig);
        // Here are the address bytes
        byte[] readyForAddress = new byte[addressBytes.length + 1 + 4];
        // prepending p2sh header:
        readyForAddress[0] = (byte) 5;
        System.arraycopy(addressBytes, 0, readyForAddress, 1, addressBytes.length);
        // But we should also append check sum:
        byte[] checkSum = Sha256Hash.hashTwice(readyForAddress, 0, addressBytes.length + 1);
        System.arraycopy(checkSum, 0, readyForAddress, addressBytes.length + 1, 4);
        // To get the final address:
        String segwitAddress = Base58.base58Encode(readyForAddress);
        System.out.println("segwit address:" + segwitAddress);
    }

    /*private static byte[] fromHex(String hex) {
        byte[] binary = new byte[hex.length() / 2];
        for (int i = 0; i < binary.length; i++) {
            binary[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return binary;

    }*/

    private static byte[] getUtf8Bytes(final String str) {
        return toRuntime(new CheckedExceptionToRuntime.Func<byte[]>() {
            @Override
            public byte[] run() throws Exception {
                return str.getBytes("UTF-8");
            }
        });
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static void genKeyStoreByPrivateKey(String ksContent, String ksName, String ksPwd) {
        ks.genKeyByPrivateKey(ksName, ksPwd);
        try {
            Thread.sleep(1000); //1000 毫秒，也就是1秒.
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
        ks.protectContent(ksContent, ksPwd);
        ks.getContent(ksPwd);
    }

    private static void genKeyStoreByMnemonic(String ksContent, String ksName, String ksPwd) {
        ks.genKeyByMnemonic(ksName, ksPwd);
        try {
            Thread.sleep(1000); //1000 毫秒，也就是1秒.
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
        ks.protectContent(ksContent, ksPwd);
        ks.getContent(ksPwd);
    }

    public static void sendTransaction(String fromAddress, String toAddress, BigDecimal amount,
                                       String password, WalletFile walletfile) throws Exception {
        new SendTransaction().sendTransaction(fromAddress, toAddress, amount, password, walletfile);
    }
}


