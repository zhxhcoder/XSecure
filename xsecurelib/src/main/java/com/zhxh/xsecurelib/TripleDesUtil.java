package com.zhxh.xsecurelib;


import java.io.UnsupportedEncodingException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TripleDesUtil {

    /**
     * 算法DESede
     */
    private static final String Algorithm = "DESede";
    /**
     * 模型
     */
    private static final String Transformation = "DESede/CBC/PKCS5Padding";
    /**
     * 秘钥
     */
    private static final String key = "这是自定义的字符串";
    /**
     * 偏移量
     */
    private static final String key_iv = "12312300";

    private static String encryptMode(byte[] src) {

        try {

            // 根据给定的字节数组和算法构造一个密钥
            SecretKey deskey = new SecretKeySpec(key.getBytes("utf-8"), Algorithm);
            // 加密
            IvParameterSpec iv = new IvParameterSpec(key_iv.getBytes("utf-8"));
            Cipher c1 = Cipher.getInstance(Transformation);
            c1.init(Cipher.ENCRYPT_MODE, deskey, iv);

            return byte2hex(c1.doFinal(src));

        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (java.lang.Exception e3) {
            e3.printStackTrace();
        }

        return null;
    }

    private static String byte2hex(byte[] b) { // 一个字节的数，
        // 转成16进制字符串
        String hs = "";
        String stmp;
        for (int n = 0; n < b.length; n++) {
            // 整数转成十六进制表示
            stmp = (java.lang.Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1)
                hs = hs + "0" + stmp;
            else
                hs = hs + stmp;
        }
        return hs; // 转成大写
    }

    /***
     * 加密
     * @param src 明文
     * @return 密文
     */
    public static String encryptMode(String src) {

        try {

            return encryptMode(src.getBytes());

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return "";
    }

    /***
     * 解密
     * @param src 密文
     * @return 明文
     */
    public static String decryptMode(String src) {

        try {

            return decryptMode(hex2byte(src.getBytes()));

        } catch (Exception ex) {
            ex.printStackTrace();
            return "";
        }
    }

    public static byte[] getKeyByte(String key)
            throws UnsupportedEncodingException {
        // 加密数据必须是24位，不足补0；超出24位则只取前面的24数据
        byte[] data = key.getBytes();
        int len = data.length;
        byte[] newdata = new byte[24];
        System.arraycopy(data, 0, newdata, 0, len > 24 ? 24 : len);
        return newdata;
    }

    private static String decryptMode(byte[] src) {
        try {
            // 生成密钥
            SecretKey deskey = new SecretKeySpec(key.getBytes("utf-8"), Algorithm);
            // 解密
            IvParameterSpec iv = new IvParameterSpec(key_iv.getBytes("utf-8"));
            Cipher c1 = Cipher.getInstance(Transformation);
            c1.init(Cipher.DECRYPT_MODE, deskey, iv);
            byte[] data = c1.doFinal(src);

            return new String(data);
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (java.lang.Exception e3) {
            e3.printStackTrace();
        }

        return null;
    }

    private static byte[] hex2byte(byte[] b) {

        if ((b.length % 2) != 0)
            throw new IllegalArgumentException("长度不是偶数");

        byte[] b2 = new byte[b.length / 2];

        for (int n = 0; n < b.length; n += 2) {
            String item = new String(b, n, 2);
            // 两位一组，表示一个字节,把这样表示的16进制字符串，还原成一个进制字节
            b2[n / 2] = (byte) Integer.parseInt(item, 16);
        }

        return b2;
    }
}
