
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.CertificateException;
import javax.crypto.spec.SecretKeySpec;


public class GenerateKeyStore {

    private String fileName = "";

    private void execCommand(String[] arstringCommand) {
        for (int i = 0; i < arstringCommand.length; i++) {
            System.out.print(arstringCommand[i] + " ");
        }
        try {
            Runtime.getRuntime().exec(arstringCommand);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public void execCommand(String arstringCommand) {
        try {
            Runtime.getRuntime().exec(arstringCommand);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * 生成密钥
     */
    public void genKeyByPrivateKey(String address, String password) {
        fileName = "/Users/terry/Documents/GitHub/BitcoinWallet/keystore/" + address + "_PrivateKey" + ".keystore";
        String[] arstringCommand = new String[]{

                "keytool",
                "-genkey", // -genkey表示生成密钥
                "-validity", // -validity指定证书有效期(单位：天)，这里是36000天
                "36500",
                "-keysize",//     指定密钥长度
                "1024",
                "-alias", // -alias指定别名，这里是ss
                "Mnemonic",
                "-keyalg", // -keyalg 指定密钥的算法 (如 RSA DSA（如果不指定默认采用DSA）)
                "RSA",
                "-keystore", // -keystore指定存储位置，这里是/Users/terry/Documents/GitHub/my/BitcoinDemo/keystore/demo.keystore
                fileName,
                "-dname",// CN=(名字与姓氏), OU=(组织单位名称), O=(组织名称), L=(城市或区域名称),
                // ST=(州或省份名称), C=(单位的两字母国家代码)"
                "CN=(user), OU=(imbuff), O=(imbuff), L=(SH), ST=(SH), C=(CN)",
                "-storepass", // 指定密钥库的密码(获取keystore信息所需的密码)
                password,
                "-keypass",// 指定别名条目的密码(私钥的密码)
                password,
                "-v"// -v 显示密钥库中的证书详细信息
        };
        execCommand(arstringCommand);
    }

    /**
     *
     */
    public void genKeyByMnemonic(String address, String password) {
        fileName = "/Users/terry/Documents/GitHub/BitcoinWallet/keystore/" + address + "_Mnemonic" + ".keystore";
        String[] arstringCommand = new String[]{

                "keytool",
                "-genkey", // -genkey表示生成密钥
                "-validity", // -validity指定证书有效期(单位：天)，这里是36000天
                "36500",
                "-keysize",//     指定密钥长度
                "1024",
                "-alias", // -alias指定别名，这里是ss
                "Mnemonic",
                "-keyalg", // -keyalg 指定密钥的算法 (如 RSA DSA（如果不指定默认采用DSA）)
                "RSA",
                "-keystore", // -keystore指定存储位置，这里是/Users/terry/Documents/GitHub/my/BitcoinDemo/keystore/demo.keystore
                fileName,
                "-dname",// CN=(名字与姓氏), OU=(组织单位名称), O=(组织名称), L=(城市或区域名称),
                // ST=(州或省份名称), C=(单位的两字母国家代码)"
                "CN=(user), OU=(imbuff), O=(imbuff), L=(SH), ST=(SH), C=(CN)",
                "-storepass", // 指定密钥库的密码(获取keystore信息所需的密码)
                password,
                "-keypass",// 指定别名条目的密码(私钥的密码)
                password,
                "-v"// -v 显示密钥库中的证书详细信息
        };
        execCommand(arstringCommand);
    }

    public void protectContent(String privateKey, String password) {
        FileInputStream fis = null;
        OutputStream os = null;
        try {
            // 读取keystore文件转换为keystore密钥库对象
            fis = new FileInputStream(fileName);
            // 生成证书的类型为jceks
            KeyStore keyStore = KeyStore.getInstance("jceks");
            // 该密钥库的密码,storepass指定密钥库的密码(获取keystore信息所需的密码)
            String storepass = password;
            keyStore.load(fis, storepass.toCharArray());
            fis.close();
            // 一旦加载了 keystore，就能够从 keystore 读取现有条目，或向 keystore 写入新条目：
            String alias = "Mnemonic";// 别名
            String keypass = password; // 别名密码 ,keypass 指定别名条目的密码(私钥的密码)
            ProtectionParameter param = new KeyStore.PasswordProtection(keypass.toCharArray());
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, param);
            PrivateKey myPrivateKey = pkEntry.getPrivateKey();
            System.out.println("获取的私钥是：" + myPrivateKey.toString());
            // 根据给定的字节数组构造一个密钥
            String desPwd = privateKey;// 用户要求保存于keystore文件中的密码
            javax.crypto.SecretKey mySecretKey = new SecretKeySpec(desPwd.getBytes(), "JKS");
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(mySecretKey);
            keyStore.setEntry(alias, skEntry, new KeyStore.PasswordProtection("decryp pwd".toCharArray()));
            //将此 keystore 存储到给定输出流，并用给定密码保护其完整性。
            os = new FileOutputStream(fileName);
            keyStore.store(os, storepass.toCharArray());
            os.close();
        } catch (KeyStoreException | NoSuchAlgorithmException | IOException | CertificateException | UnrecoverableEntryException e) {
            e.printStackTrace();
        } finally {
            try {
                if (os != null)
                    os.close();
                if (fis != null)
                    fis.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void getContent(String password) {
        String storepass = password;
        try {
            FileInputStream fis = null;
            // 读取keystore文件转换为keystore密钥库对象
            fis = new FileInputStream(fileName);
            // 因为生成证书的类型为JKS 也有其他的格式
            KeyStore keyStore = KeyStore.getInstance("jceks");
            // 该密钥库的密码"888999",storepass指定密钥库的密码(获取keystore信息所需的密码)
            keyStore.load(fis, storepass.toCharArray());
            fis.close();
            // 根据别名（alias=desPws）从证书（keyStore）获取密码并解密
            //keyStore.getKey返回与给定别名关联的密钥，并用给定密码来恢复它。
            Key key = keyStore.getKey("Mnemonic", "decryp pwd".toCharArray());
            //key.getEncoded()返回基本编码格式的密钥，如果此密钥不支持编码，则返回 null。
            byte[] bt = key.getEncoded();
            StringBuilder privateKey = new StringBuilder();
            System.out.println("从证书中获取的内容是：");
            for (int i = 0; i < bt.length; i++) {
                char ch = (char) bt[i];
                privateKey.append(ch);
                System.out.print(ch);
            }

        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
            System.out.println("wrong password !");
        }
    }


}

