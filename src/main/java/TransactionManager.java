import io.github.novacrypto.bip32.networks.Bitcoin;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.*;
import org.web3j.tx.ChainId;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;

public class TransactionManager {

    /**
     * ETH 转账离线签名
     *
     * @param to         转入的钱包地址
     * @param nonce      以太坊nonce
     * @param gasPrice   gasPrice
     * @param gasLimit   gasLimit
     * @param amount     转账的eth数量
     * @param walletfile 钱包对象
     * @param password   密码
     * @return 签名data
     */
    public String signedEthTransactionData(String to, BigInteger nonce, BigInteger gasPrice,
                                           BigInteger gasLimit, BigDecimal amount, WalletFile walletfile,
                                           String password) throws Exception {
        // 把十进制的转换成ETH的Wei, 1ETH = 10^18 Wei
        BigDecimal amountInWei = Convert.toWei(amount.toString(), Convert.Unit.ETHER);
        RawTransaction rawTransaction =
                RawTransaction.createEtherTransaction(nonce, gasPrice, gasLimit, to,
                        amountInWei.toBigInteger());
        return signData(rawTransaction, walletfile, password);
    }

    public String signData(RawTransaction rawTransaction, WalletFile walletfile, String password)
            throws Exception {
        Credentials credentials = Credentials.create(Wallet.decrypt(password, walletfile));
        byte[] signMessage =
                TransactionEncoder.signMessage(rawTransaction, ChainId.ROPSTEN, credentials);
        return Numeric.toHexString(signMessage);

    }

    public String signContractTransaction(String contractAddress,
                                          String to,
                                          BigInteger nonce,
                                          BigInteger gasPrice,
                                          BigInteger gasLimit,
                                          BigDecimal amount,
                                          BigDecimal decimal,
                                          WalletFile walletfile,
                                          String password) throws Exception {
        BigDecimal realValue = amount.multiply(decimal);
        Function function = new Function("transfer",
                Arrays.asList(new Address(to), new Uint256(realValue.toBigInteger())),
                Collections.emptyList());
        String data = FunctionEncoder.encode(function);
        RawTransaction rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                gasLimit,
                contractAddress,
                data);
        return signData(rawTransaction, walletfile, password);
    }

    // ---------------- singleton stuff --------------------------
    public static TransactionManager shared() {
        return TransactionManager.Holder.singleton;
    }

    public TransactionManager() {

    }

    private static class Holder {

        private static final TransactionManager singleton = new TransactionManager();

    }
}
