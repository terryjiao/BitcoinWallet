# Ethereum Wallet

Generating ETH key pairs and address from mnemonic.


----------


### 1. From entropy to mnemonic

#####1. Generating 128 digits random entropy
```java
UUID uuid = UUID.randomUUID();
String[] digits = uuid.toString().split("\\-");
StringBuilder randomDigits = new StringBuilder();
for (String digit : digits) {
    randomDigits.append(digit);
}
```

#####2. Doing SHA256 to entropy for checksum, append first 4 bits to the end of entropy
```java
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
```
#####3. Segment 132 bits entropy into 11 bits long parts
```java
String[] segments = new String[12];
for (int i = 0; i <= 11; i++) {
    segments[i] = bin_entropy.substring(i * 11, (i + 1) * 11);
}
```
#####4. Generating mnemonic from dictionary
```java
mnemonic += wordlist[Integer.valueOf(segments[0], 2)];
for (int j = 1; j < segments.length; j++) {
    mnemonic += " " + (wordlist[Integer.valueOf(segments[j], 2)]);
}
```
![enter image description here](https://upload-images.jianshu.io/upload_images/10931084-93b10c15c7277420.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/700)


----------


### 2. From mnemonic to seed

Using PBKDF2 function to get 512 bits seed from mnemonic.
In this part we need a salt string to generate the seed we needed. Normally the value of salt is "mnemonic" for universality

```java
String seed;
String salt = "mnemonic";
seed = getSeed(mnemonic, salt);
```
![enter image description here](https://upload-images.jianshu.io/upload_images/10931084-eb8d30c6fc836a5b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/700)


----------


###3. From seed to master private key

Divide 512 bits seed into two equal parts, the first 256 bits is master private key and the last 256 bits is chain code. We could use BIP32 library to do the jobs by APIs this library provided.

```java
ExtendedPrivateKey rootKey = ExtendedPrivateKey.fromSeed(hexStringToByteArray(seed), Bitcoin.MAIN_NET);
```
![enter image description here](https://upload-images.jianshu.io/upload_images/10931084-177ace609e88a5a3.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/700)

----------
###4. From master private key to child private key
Firstly, generate address index to get 0th private key generated from master private key and chain code.
```java
AddressIndex ethAddressIndex = BIP44.m().purpose44().coinType(60).account(0).external().address(0);
```
44.60.0.0.0 is eth address index.

And then get key pair and address that we need.
```java
ExtendedPrivateKey childPrivateKey = rootKey.derive(ethAddressIndex, AddressIndex.DERIVATION);
byte[] privateKeyBytes = childPrivateKey.getKey(); 
ECKeyPair keyPair = ECKeyPair.create(privateKeyBytes);
List<String> returnList = EthAddress(childPrivateKey, keyPair);
```

![enter image description here](https://upload-images.jianshu.io/upload_images/10931084-dfd91a5ee94953e7.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/700)
