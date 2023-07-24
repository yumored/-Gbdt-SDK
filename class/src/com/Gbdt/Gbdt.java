package com.Gbdt;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.sun.org.apache.xpath.internal.operations.Bool;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.alibaba.fastjson.JSONObject;
import sun.security.provider.MD5;

public class Gbdt {

    private String appkey;
    private String token;
    private String key;
    final static Base64.Encoder encoder = Base64.getEncoder();
    final static Base64.Decoder decoder = Base64.getDecoder();



    /*
select方法
*/
    public static String select(String table,String column, String value, String limit,String type) {
        String columd;
        String data10;
        if (column == "" || column == null) {
            return "false";
        }else{
           String acolumd =column.replace(",", "\',\'");
            String bcolumd = acolumd.replace("[", "[\'");
            columd = bcolumd.replace("]", "\']");
        }
        if (value == "*") {
            data10 = "\"*\"";
        } else {
            if (value != "" || value != null) {
                    String data1 = value.replace("[", "{\"");
                    String data2 = data1.replace("=>", "\":\"");
                    String data3 = data2.replace("]", "\"}");
                    String data4 = data3 .replace("?>", "[~]\":\"");
                    String data5 = data4 .replace("!>", "[!~]");
                    data10 = data5.replace(",", "\",\"");

            } else {
                return "false";
            }
        }
        String jsondata = "{\"table\":\"" + table + "\",\"column\":\""+ columd + "\",\"value\":" + data10 + ",\"type\":" + type+ ",\"limit\":\"" + limit + "\"}";
        return jsondata;
    }
    /*
update方法
*/
    public static String update(String table,String column, String value) {
        String datalnd = column;
        if (column == "" || column == null) {
            datalnd = "false";
        }else {
            boolean status = datalnd.contains("=>");
            if (status) {
                String dataIndexes1 = column.replace("[", "{\"");
                String dataIndexes2 = dataIndexes1.replace("=>", "\":\"");
                String dataIndexes3 = dataIndexes2.replace("]", "\"}");
                datalnd = dataIndexes3.replace(",", "\",\"");
            } else {
                String dataIndexes1 = column.replace("[", "[\"");
                String dataIndexes2 = dataIndexes1.replace("]", "\"]");
                datalnd = dataIndexes2.replace(",", "\",\"");
            }
        }
        String data4;
            if (value != "" || value != null) {
                String data1 = value.replace("[", "{\"");
                String data2 = data1.replace("=>", "\":\"");
                String data3 = data2.replace("]", "\"}");
                data4 = data3.replace(",", "\",\"");
            } else {
                return "参数提交错误";
            }
        String jsondata = "{\"table\":\"" + table + "\",\"column\":" + datalnd + ",\"value\":" + data4 + "}";
        return jsondata;
    }
    /*
delete/insert方法
*/
    public static String deleins(String table,String value) {
        String data4;
        if (value != "" || value != null) {
            String data1 = value.replace("[", "{\"");
            String data2 = data1.replace("=>", "\":\"");
            String data3 = data2.replace("]", "\"}");
            data4 = data3.replace(",", "\",\"");
        } else {
            return "false";
        }
        String jsondata = "{\"table\":\"" + table +  "\",\"value\":" + data4 + "}";
        return jsondata;
    }

    /*
    列队封装
    */
    public static String synthesis(String table,String column, String value, String limit,String type) {
        column = column.replace(",", "\",\"");
        String []arr_column=column.split("/");
        column="";
        for (int i=0;arr_column.length>i;i++){
            arr_column[i]=arr_column[i].replace("[", "[\"");
            arr_column[i]=arr_column[i].replace("]", "\"]");
            if(arr_column[i].contains("=>")){
                if (arr_column.length > i + 1) {
                    column = column + arr_column[i].replace("=>", "\":\"").replace("[", "{").replace("]", "\"}") + ",";
                } else {
                    column = column + arr_column[i].replace("=>", "\":\"").replace("[", "{").replace("]", "}");
                }
            }
            else if(arr_column[i].contains("?>")){
                if (arr_column.length > i + 1) {
                    column = column + arr_column[i].replace("[", "{").replace("]", "}").replace("?>", "[~]\":\"") + ",";
                } else {
                    column = column + arr_column[i].replace("[", "{").replace("]", "}").replace("?>", "[~]\":\"");
                }
            }
            else if(arr_column[i].contains("!>")) {
                if (arr_column.length > i + 1) {
                    column = column + arr_column[i].replace("[", "{").replace("]", "}").replace("!>", "[!~]\":\"") + ",";
                } else {
                    column = column + arr_column[i].replace("[", "{").replace("]", "}").replace("!>", "[!~]\":\"");
                }
            }
            else {
                if (arr_column.length > i + 1) {
                    column = column + arr_column[i] + ",";
                } else {
                    column = column + arr_column[i];
                }
            }
        }
        column="["+column+"]";
        //
        value = value.replace(",", "\",\"");
        String []arr_value=value.split("/");
        value="";
        for (int i=0;arr_value.length>i;i++){
            if(arr_value[i].contains("=>")){
                if (arr_value.length > i + 1) {
                    value = value + arr_value[i].replace("=>", "\":\"").replace("[", "{\"").replace("]", "\"}") + ",";
                } else {
                    value = value + arr_value[i].replace("=>", "\":\"").replace("[", "{\"").replace("]", "\"}");
                }
            }
            else if(arr_value[i].contains("?>")){
                if (arr_value.length > i + 1) {
                    value = value + arr_value[i].replace("[", "{\"").replace("]", "\"}").replace("?>", "[~]\":\"") + ",";
                } else {
                    value = value + arr_value[i].replace("[", "{\"").replace("]", "\"}").replace("?>", "[~]\":\"");
                }
            }
            else if(arr_value[i].contains("!>")) {
                if (arr_value.length > i + 1) {
                    value = value + arr_value[i].replace("[", "{\"").replace("]", "\"}").replace("!>", "[!~]\":\"") + ",";
                } else {
                    value = value + arr_value[i].replace("[", "{\"").replace("]", "\"}").replace("!>", "[!~]\":\"");
                }
            }else {
                if (arr_value.length > i + 1) {
                    value = value + arr_value[i] + ",";
                } else {
                    value = value + arr_value[i];
                }
            }
        }
        value="["+value+"]";
        //
        String []arr_limit=limit.split("/");
        limit="";
        for (int i=0;arr_limit.length>i;i++){
            if (arr_limit.length > i + 1) {
                if(arr_limit[i].contains("[") && arr_limit[i].contains("]")){
                    limit = limit + arr_limit[i] + ",";
                }else{
                    limit = limit + "\""+arr_limit[i] + "\",";
                }
            } else {
                if(arr_limit[i].contains("[") && arr_limit[i].contains("]")){
                    limit = limit +arr_limit[i]+"]";
                }else{
                    limit = limit + "\""+arr_limit[i]+"\"]";
                }
            }
        }
        //
        String []arr_type=type.split("/");
        type="";
        for (int i=0;arr_type.length>i;i++){
            if (arr_type.length > i + 1) {
                    type = type + "\""+arr_type[i] + "\",";
            } else {
                type = type + "\""+arr_type[i]+"\"";
            }
        }
        //
        String []arr_table=table.split("/");
        table="";
        for (int i=0;arr_table.length>i;i++){
            if (arr_table.length > i + 1) {
                table = table + "\""+arr_table[i] + "\",";
            } else {
                table = table + "\""+arr_table[i]+"\"";
            }
        }
        String jsondata = "{\"table\":[" + table + "],\"column\":"+ column + ",\"value\":" + value + ",\"type\":[" + type+ "],\"limit\":["+ limit + "}";
        return jsondata;
    }
    /*
    总数据分配
     */
    public static String data(String info,String type,String table, String column, String limit, String value,String _type) {
        String df="";
        JSONObject _info= JSON.parseObject(info);
        String user=_info.getString("user").intern();
        String pass=_info.getString("pass").intern();
        String token=_info.getString("token").intern();
        String key=_info.getString("key").intern();
        String data_key=_info.getString("data_key").intern();
        String jsondata="无数据";
        String []arr=table.split("/");
        if (arr.length==1) {
            if (type.contains("select")) {
                jsondata = select(table, column, value, limit, _type);
            } else if (type.contains("update")) {
                jsondata = update(table, column, value);
            } else if (type.contains("delete")) {
                jsondata = deleins(table, value);
            } else if (type.contains("insert")) {
                jsondata = deleins(table, value);
            }
            df = rate(type, user, pass, jsondata, token, key, data_key,false);
        }else{
            String []arr_type=type.split("/");
            type="";
            for (int i=0;arr_type.length>i;i++){
                if (arr_type.length > i + 1) {
                    type = type + "\""+arr_type[i] + "\",";
                } else {
                    type = type + "\""+arr_type[i]+"\"";
                }
            }
            jsondata = synthesis(table, column, value, limit, _type);
            df = rate("["+type+"]", user, pass, jsondata, token, key, data_key,true);
        }
        return df;
    }
    /*
    合成
     */
    public static String rate(String type, String user, String pass, String data, String token, String key, String data_key, boolean _true) {
        Gbdt dete = new Gbdt();
        String json1="";
        if(_true){
            json1 = "{\"type\":" + type + ",\"user\":\"" + user + "\",\"pass\":\"" + pass + "\",\"data\":" + data + "}";
        }else{
            json1 = "{\"type\":\"" + type + "\",\"user\":\"" + user + "\",\"pass\":\"" + pass + "\",\"data\":" + data + "}";
        }
        System.out.println(json1);
    String data_AES_json = dete.encryptString(json1, key);
    Pattern p = Pattern.compile("\\s*|\t|\n");
    Matcher m = p.matcher(data_AES_json);
    data_AES_json =m.replaceAll("");
    String a = dete.MD5(user,pass, token, data_key, json1);
    String json = toUtf8String("{\"data\":\"" + data_AES_json + "\",\"MD5\":" + a + "}");
        return "data="+json;
    }
    public static String untie(String info,String data){
        //String url_data=URLDecoder.decode(data,"UTF-8");
        try {
        Gbdt Gbdt=new Gbdt();
        JSONObject jsonObject= JSON.parseObject(data);
        String _MD5=jsonObject.getString("MD5");
        String _data=jsonObject.getString("data");
        JSONObject MD5= JSON.parseObject(_MD5);
        String _MD5_user=MD5.getString("_user").intern();
        String _MD5_nonce=MD5.getString("_nonce").intern();
        String _MD5_sign=MD5.getString("_sign").intern();
        String _MD5_time=MD5.getString("_time").intern();
        //
        JSONObject _jsonObject= JSON.parseObject(info);
        String _user=_jsonObject.getString("user").intern();
        String _pass=_jsonObject.getString("pass").intern();
        String _token=_jsonObject.getString("token").intern();
        String _key=_jsonObject.getString("key");
        String _data_key=_jsonObject.getString("data_key").intern();
        if(_MD5_user!=_user)return "{\"code\":\"-1\",\"msg\":\"MD5账号错误\"}";
        String _AES= Gbdt.dencryptString(_data,_key);
        _AES = _AES.replaceAll("\\p{C}", "").intern();
        if(!Gbdt.untieMD5(_user,_pass,_MD5_nonce,_MD5_sign,_MD5_time,_token,_data_key,_data))return "{\"code\":\"-1\",\"msg\":\"MD5签名校验失败\"}";
        return _AES;
        } catch (Exception e) {
            return "{\"code\":\"-1\"}";
        }
    }

    //解密
    public static String encode(String text) {
        return encoder.encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }
    //加密
    public static String decode(String encodedText) {
        return new String(decoder.decode(encodedText), StandardCharsets.UTF_8);
    }
    /*
    AES加/解密方法
     */
    public static String AES_encryptString(String data,String key){
        Gbdt dete =new Gbdt();
        String data_AES_json=dete.encryptString(data,key);
        return data_AES_json;
    }
    public static String AES_dencryptString(String data,String key){
        Gbdt dete =new Gbdt();
        String data_AES_json=dete.dencryptString(data,key);
        return data_AES_json;
    }
    /*
    -
     */

    public static final String HMAC_MD5 = "HmacMD5";
    public String MD5(String user,String appkey, String token, String key ,String jsondata) {
        this.appkey=appkey;
        this.token=token;
        this.key=key;
        String nonce=getRandom(32);
        long time=(new Date().getTime()/1000);
        String signature="_key="+appkey+"&_nonce="+nonce+"&_time="+time+"&token="+token+"&json="+jsondata;
        String sig = Gbdt.encrypt(signature, key, Gbdt.HMAC_MD5);
        String json = "{\"_user\":\""+user+"\",\"_nonce\":\""+nonce+"\",\"_sign\":\""+sig+"\",\"_time\":\""+time+"\",\"_token\":\""+token+"\"}";
        return json;
    }
    public boolean untieMD5(String user,String appkey,String nonce,String sign,String time, String token, String key ,String jsondata){
        if(user=="" && appkey=="" && token=="" && key=="" && jsondata=="")return false;
        String __signa="_key="+appkey+"&_nonce="+nonce+"&_time="+time+"&token="+token+"&json="+jsondata;
        String _signa=__signa.intern();
        long _time=(new Date().getTime()/1000);
        if (nonce.length()!= 32)return false;
        if (_time - Integer.parseInt(time) > 5)return false;
        String sig = Gbdt.encrypt(_signa, key, Gbdt.HMAC_MD5);
        if (sig.intern() != sign) return false;
            return true;
    }

    public static String getRandom(int param){
        Random random=new Random();
        String[] str={"0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"};
        String key = "";
        for(int i=0;i<param;i++)
        {
             key =str[random.nextInt(33)]+key;
        }
        return key;
    }




    /**
     * 实现Hmac系列的加密算法HmacSHA1、HmacMD5等
     *
     * @param input 需要加密的输入参数
     * @param key 密钥
     * @param algorithm 选择加密算法
     * @return 加密后的值
     **/
    public static String encrypt(String input, String key, String algorithm) {
        String cipher = "";
        try {
            byte[] data = key.getBytes(StandardCharsets.UTF_8);
            //根据给定的字节数组构造一个密钥，第二个参数指定一个密钥的算法名称，生成HmacSHA1专属密钥
            SecretKey secretKey = new SecretKeySpec(data, algorithm);

            //生成一个指定Mac算法的Mac对象
            Mac mac = Mac.getInstance(algorithm);
            //用给定密钥初始化Mac对象
            mac.init(secretKey);
            byte[] text = input.getBytes(StandardCharsets.UTF_8);
            byte[] encryptByte = mac.doFinal(text);
            cipher = bytesToHexStr(encryptByte);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return cipher;
    }





    /**
     * byte数组转16进制字符串
     *
     * @param  bytes byte数组
     * @return hex字符串
     */
    public static String bytesToHexStr(byte[] bytes) {
        StringBuilder hexStr = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            hexStr.append(hex);
        }
        return hexStr.toString();
    }


    /* AES加密， 输入原字符串 和 一个自定义密钥。输出加密字符串
     */
    public String encryptString(String st, String key)
    {
        return encrypt(st, md5st(key).substring(8,24));
    }
    /**
     * AES解密， 输入加密字符串 和 一个自定义密钥。输出原字符串
     */
    public String dencryptString(String st, String key)
    {
        return decrypt(st, md5st(key).substring(8,24));
    }

    /**
     * md5加密，输入字符串
     * */
    public String md5st(String btInput) {
        return md5(btInput.getBytes());
    }
    /**
     * md5加密，输入字节组
     * */
    public String md5(byte[] btInput) {
        char[] hexDigits = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
        try {
            java.security.MessageDigest mdInst = java.security.MessageDigest.getInstance("MD5");
            mdInst.update(btInput);
            byte[] md = mdInst.digest();
            int j = md.length;
            char[] str = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(str);
        } catch (java.lang.Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    //字符串加密
    public String encrypt(String data, String key)
    {
        final BASE64Encoder encoder = new BASE64Encoder();
  /*
   String data = "Test String";
      String key = "1234567812345678";
      String iv = "1234567812345678";
      */
        String iv=key;

        byte[] dataBytes = data.getBytes();
        Cipher localCipher = null;
        try {
            localCipher = Cipher.getInstance("AES/CBC/NoPadding");
            //AES/CBC/NoPadding
        } catch (Exception e) {
            e.printStackTrace();
        }

        if(localCipher != null)
        {
            try {
                int blockSize = localCipher.getBlockSize();
                int plaintextLength = dataBytes.length;
                if (plaintextLength % blockSize != 0) {
                    plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
                }
                byte[] plaintext = new byte[plaintextLength];
                System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);
                localCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"), new IvParameterSpec(iv.getBytes()));
                byte[] encrypted = localCipher.doFinal(plaintext);
                //return new sun.misc.BASE64Encoder().encode(encrypted);

                return encoder.encode(encrypted).trim();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }


    //字符串解密
    public String decrypt(String data,String key) {
        javax.crypto.Cipher localCipher = null;
        BASE64Decoder decoder = new BASE64Decoder();
 /*
   String data = "2fbwW9+8vPId2/foafZq6Q==";
      String key = "1234567812345678";
      String iv = "1234567812345678";
      */
        String iv=key;
        try {
            localCipher = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding");
        } catch (java.lang.Exception e) {
            e.printStackTrace();
        }


        if(localCipher != null)
        {
            try {
                localCipher= javax.crypto.Cipher.getInstance("AES/CBC/NoPadding");
                localCipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key.getBytes(), "AES"), new javax.crypto.spec.IvParameterSpec(key.getBytes()));;
                byte[] original = localCipher.doFinal(decoder.decodeBuffer(data));
                return new String(original);

            } catch (java.lang.Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    /**
     * 字符串转换UTF-8编码
     *
     * @param string 字符串
     * @return java.lang.String
     * @date 2022/4/14.
     */
    public static String toUtf8String(String string) {
        StringBuilder stringBuffer = new StringBuilder();
        for (int i = 0; i < string.length(); i++) {
            char c = string.charAt(i);
            byte[] b;
            try {
                b = Character.toString(c).getBytes(StandardCharsets.UTF_8);
            } catch (Exception ex) {
                b = new byte[0];
            }
            for (int value : b) {
                int k = value;
                if (k < 0) k += 256;
                stringBuffer.append("%").append(Integer.toHexString(k).toUpperCase());
            }
        }
        return stringBuffer.toString();
    }

}



