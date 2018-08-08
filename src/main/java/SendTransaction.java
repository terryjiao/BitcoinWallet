
import org.web3j.crypto.WalletFile;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.*;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class SendTransaction {

    private Web3j web3j = Web3j.build(new HttpService("https://test-eth.nshd.com"));

    public void sendTransaction(String fromAddress, String toAddress, BigDecimal amount, String password, WalletFile walletfile) throws Exception {
        BigInteger mNonce = getNonce(fromAddress);
        BigInteger gasPrice = getGasPrice();
        BigInteger value = Convert.toWei(amount, Convert.Unit.ETHER).toBigInteger();
        Transaction transaction = Transaction.createEtherTransaction(fromAddress, null,
                null, null, toAddress, value);
        BigInteger gasLimit = getGasLimit(transaction);
        String sign = new TransactionManager().signedEthTransactionData(toAddress, mNonce, gasPrice,
                gasLimit, amount, walletfile, password);
        sendTransaction(sign);

    }

    public BigInteger getBalance(String fromAddress){
        BigInteger balance = null;
        try {
            EthGetBalance ethGetBalance = web3j.ethGetBalance(fromAddress, DefaultBlockParameterName.PENDING).send();
            balance = ethGetBalance.getBalance();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("address " + fromAddress + " balance " + balance + " wei");
        return balance;
    }

    private BigInteger getNonce(String userAddress) {
        BigInteger nonce = BigInteger.ONE;
        try {
            Request<?, EthGetTransactionCount> rs = web3j.ethGetTransactionCount(
                    userAddress, DefaultBlockParameterName.PENDING);
            EthGetTransactionCount egtc = rs.sendAsync().get();
            nonce = egtc.getTransactionCount();
        } catch (Exception e) {
            System.out.println("" + e);
        }
        return nonce;
    }

    private BigInteger getGasPrice() {
        BigInteger gasPrice = BigInteger.ONE;
        try {
            Request<?, EthGasPrice> rs = web3j.ethGasPrice();
            EthGasPrice eGasPrice = rs.sendAsync().get();
            gasPrice = eGasPrice.getGasPrice();
        } catch (Exception e) {
            System.out.println("" + e);
        }
        return gasPrice;
    }

    private BigInteger getGasLimit(Transaction transaction) {
        BigInteger gasLimit = BigInteger.ONE;
        try {
            Request<?, EthEstimateGas> rs = web3j.ethEstimateGas(transaction);
            EthEstimateGas eGasLimit = rs.sendAsync().get();
            gasLimit = eGasLimit.getAmountUsed();
        } catch (Exception e) {
            System.out.println("" + e);
        }
        return gasLimit;
    }

    private void sendTransaction(String sign){
        try {
            Request<?, EthSendTransaction> rs = web3j.ethSendRawTransaction(sign);
            EthSendTransaction eSendTransaction = rs.sendAsync().get();
            String res = eSendTransaction.getTransactionHash();
            System.out.println("send hash :  " + res);
        } catch (Exception e) {
            System.out.println("" + e);
        }
    }
}
