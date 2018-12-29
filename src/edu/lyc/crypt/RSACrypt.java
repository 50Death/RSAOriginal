package edu.lyc.crypt;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;
import java.util.Scanner;

public class RSACrypt {
    public BigInteger n, e;//公钥
    public BigInteger d;//私钥+n
    public BigInteger p, q;
    public BigInteger eul;//n的欧拉函数

    private void init(int len) {
        Random random = new Random();
        //产生大素数p,q
        p = BigInteger.probablePrime(len, random);
        q = BigInteger.probablePrime(len, random);

        n = p.multiply(q);
        eul = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        creatExpenent(eul);
    }

    private BigInteger encryptByPublic(BigInteger m) {
        return m.modPow(e, n);
    }

    private BigInteger decryptByPrivate(BigInteger c) {
        return c.modPow(d, n);
    }

    private void creatExpenent(BigInteger eul) {
        e = new BigInteger("65537");
        d = e.modInverse(eul);
    }

    /**
     * 执行函数
     *
     * @param mode       String类型，ENCRYPT_MODE为加密模式，DECRYPT_MODE为解密模式
     * @param plainText  字符串明文
     * @param privateKey 私钥需要输入
     * @return 密文
     */
    public String doFinal(String mode, String plainText, String privateKey) {
        if (mode.equals("ENCRYPT_MODE")) {
            BigInteger plainTextBigInteger = strToHex(plainText);//将字符串转为16进制BigInteger，以10进制的方式存入
            int length = plainTextBigInteger.bitLength();
            init(length);
            BigInteger encryptText = encryptByPublic(plainTextBigInteger);
            return encryptText.toString();
        } else if (mode.equals("DECRYPT_MODE")) {
            BigInteger cipherText = new BigInteger(plainText);
            String[] str = privateKey.substring(1, privateKey.length() - 1).split(",");
            BigInteger newN = new BigInteger(str[0]);
            BigInteger newD = new BigInteger(str[1]);
            n = newN;
            d = newD;
            String result = hexToStr(decryptByPrivate(cipherText));
            return result;

        } else {
            throw new IllegalStateException();
        }
    }

    private BigInteger strToHex(String text) {
        char[] asciiText = text.toCharArray();
        String hexText = new String();
        for (int i = 0; i < asciiText.length; i++) {
            Integer integer = (int) asciiText[i];
            hexText += Integer.toHexString(integer);
        }
        BigInteger result = new BigInteger(hexText);
        return result;
    }

    private String hexToStr(BigInteger bi){
        char[] charsASCII = new char[bi.toString().length()/2+1];
        int num=0;
        for(int i=0;i<bi.toString().length();i+=2){
            String temp = new BigInteger(bi.toString().substring(i,i+2),16).toString(10);
            int ascii = Integer.parseInt(temp);
            char charASCII = (char) ascii;
            charsASCII[num]=charASCII;
            num++;
        }
        String result = new String(charsASCII);
        return result;
    }

    public static void main(String[] args) {
        RSACrypt rsaCrypt = new RSACrypt();
        System.out.println("Usage：Input the front number to select option\n1.Encrypt\n2.Decrypt");
        Scanner sc = new Scanner(System.in);
        while (true) {
            int mode = sc.nextInt();
            sc.nextLine();
            if (mode == 1) {
                System.out.println("Input Text: ");
                String text = sc.nextLine();
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                System.out.println("Start ciphering at " + sdf.format(new Date()));
                String result = rsaCrypt.doFinal("ENCRYPT_MODE", text, null);
                System.out.println("PublicKey: (" + rsaCrypt.n + "," + rsaCrypt.e + ")");
                System.out.println("PrivateKey: (" + rsaCrypt.n + "," + rsaCrypt.d + ")");
                System.out.println("Ciphered Text: " + result);
            } else if (mode == 2) {
                System.out.println("Input Text: ");
                String text = sc.nextLine();
                System.out.println("Input PrivateKey: ");
                String privateKey = sc.nextLine();
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                System.out.println("Start deciphering at " + sdf.format(new Date()));
                String result = rsaCrypt.doFinal("DECRYPT_MODE", text, privateKey);
                System.out.println("Original Text: " + result);
            }
        }
    }
}
