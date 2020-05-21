/**
 * Copyright (c) 2012 YCSB contributors. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License. See accompanying
 * LICENSE file.
 */

/**
 * Redis client binding for YCSB.
 *
 * All YCSB records are mapped to a Redis *hash field*.  For scanning
 * operations, all keys are saved (by an arbitrary hash) in a sorted set.
 */

package site.ycsb.db;

import site.ycsb.ByteIterator;
import site.ycsb.DB;
import site.ycsb.DBException;
import site.ycsb.Status;
import site.ycsb.StringByteIterator;
import redis.clients.jedis.BasicCommands;
import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisCluster;
import redis.clients.jedis.JedisCommands;
import redis.clients.jedis.Protocol;

import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;

import java.security.spec.KeySpec;
import java.security.SecureRandom;
import java.security.MessageDigest;  
import java.security.NoSuchAlgorithmException;

import java.util.Base64;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * YCSB binding for <a href="http://redis.io/">Redis</a>.
 *
 * See {@code redis/README.md} for details.
 */
public class RedisClient extends DB {

  private JedisCommands jedis;
  private JedisCommands consumerJedis;

  private static SecretKeySpec secretKey;
  private static SecureRandom randomSecureRandom;

  private static byte[] _key = new byte[16];
  private static byte[] _salt = new byte[16];
  private static int remote_ratio = 2;
  private static AtomicInteger counter = new AtomicInteger(0);
  
  public static final String HOST_PROPERTY = "redis.host";
  public static final String PORT_PROPERTY = "redis.port";
  public static final String PASSWORD_PROPERTY = "redis.password";
  public static final String CLUSTER_PROPERTY = "redis.cluster";

  public static final String CONSUMER_HOST_PROPERTY = "redis.consumer_host";
  public static final String CONSUMER_PORT_PROPERTY = "redis.consumer_port";
  public static final String CONSUMER_PASSWORD_PROPERTY = "redis.consumer_password";
  public static final String REMOTE_RATIO_PROPERTY = "redis.remote_ratio";

  public static final String INDEX_KEY = "_indices";

  public static String getNextKp() {
    return Integer.toString(counter.getAndIncrement());
  }

  public static Boolean is_remote(String kp) {
    int number = Integer.parseInt(kp);
    if (number % 10 < remote_ratio) {
      return true;
    }
    return false;
  }

  public void crypt_init() {
    try {
      randomSecureRandom = new SecureRandom();
      randomSecureRandom.nextBytes(_key);
      randomSecureRandom.nextBytes(_salt);

      String keyString = new String(_key);
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      KeySpec spec = new PBEKeySpec(keyString.toCharArray(), _salt, 65536, 128);
      SecretKey tmp = factory.generateSecret(spec);
      secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

    } catch(Exception e) {
      System.out.println("Error while crypt init: " + e.toString());
    }
  }

  public void init() throws DBException {
    Properties props = getProperties();
    int port;
    int consumerPort;

    String portString = props.getProperty(PORT_PROPERTY);
    if (portString != null) {
      port = Integer.parseInt(portString);
    } else {
      port = Protocol.DEFAULT_PORT;
    }

    String consumerPortString = props.getProperty(CONSUMER_PORT_PROPERTY);
    if (consumerPortString != null) {
      consumerPort = Integer.parseInt(consumerPortString);
    } else {
      consumerPort = Protocol.DEFAULT_PORT;
    }

    String host = props.getProperty(HOST_PROPERTY);
    String consumerHost = props.getProperty(CONSUMER_HOST_PROPERTY);

    boolean clusterEnabled = Boolean.parseBoolean(props.getProperty(CLUSTER_PROPERTY));
    if (clusterEnabled) {
      Set<HostAndPort> jedisClusterNodes = new HashSet<>();
      jedisClusterNodes.add(new HostAndPort(host, port));
      jedis = new JedisCluster(jedisClusterNodes);
    } else {
      jedis = new Jedis(host, port);
      ((Jedis) jedis).connect();
    }

    consumerJedis = new Jedis(consumerHost, consumerPort);
    ((Jedis) consumerJedis).connect();

    String password = props.getProperty(PASSWORD_PROPERTY);
    if (password != null) {
      ((BasicCommands) jedis).auth(password);
    }

    String consumerPassword = props.getProperty(CONSUMER_PASSWORD_PROPERTY);
    if (consumerPassword != null) {
      ((BasicCommands) consumerJedis).auth(consumerPassword);
    }

    String remoteRatio = props.getProperty(REMOTE_RATIO_PROPERTY);
    if (remoteRatio != null) {
      remote_ratio = Integer.parseInt(remoteRatio);
    }
    crypt_init();
  }

  public static byte[] getIV(int size) {
    byte[] iv = new byte[size];
    randomSecureRandom.nextBytes(iv);
    //System.out.println("IV: " + iv);
    return iv;
  }

  public static byte[] getSHA(String input) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      return md.digest(input.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      System.out.println("Error while SHA: " + e.toString());
    }
    return null;
  }

  public static String encrypt(String strToEncrypt) {
    try{
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      byte[] iv = getIV(cipher.getBlockSize());
      IvParameterSpec ivspec = new IvParameterSpec(iv);
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
      byte[] encryptBytes = cipher.doFinal(strToEncrypt.getBytes());
      byte[] f = new byte[iv.length + encryptBytes.length];
      System.arraycopy(iv, 0, f, 0, iv.length);
      System.arraycopy(encryptBytes, 0, f, iv.length, encryptBytes.length);
      //System.out.println("IV length: " + iv.length + ", encryption length: " + encryptBytes.length + ", total: "+ f.length);

      return Base64.getEncoder().encodeToString(f);
    } catch (Exception e) {
        System.out.println("Error while encrypting: " + e.toString());
    }
    return null;
  }

  public static String decrypt(String strToDecrypt) {
    try{
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      byte[] toDecryptByte = Base64.getDecoder().decode(strToDecrypt);
      
      byte[] iv = Arrays.copyOfRange(toDecryptByte, 0, cipher.getBlockSize());
      IvParameterSpec ivspec = new IvParameterSpec(iv);
      byte[] textToDecipherWithoutIv = Arrays.copyOfRange(toDecryptByte, cipher.getBlockSize(), toDecryptByte.length);

      //System.out.println("IV length: " + iv.length + ", deryption length: " + textToDecipherWithoutIv.length + ", total: "+ toDecryptByte.length);
      cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
      return new String(cipher.doFinal(textToDecipherWithoutIv));
    } catch (Exception e) {
        System.out.println("Error while decrypting: " + e.toString());
    }
    return null;
  }

  public void cleanup() throws DBException {
    try {
      ((Closeable) jedis).close();
    } catch (IOException e) {
      throw new DBException("Closing connection failed.");
    }
  }

  /*
   * Calculate a hash for a key to store it in an index. The actual return value
   * of this function is not interesting -- it primarily needs to be fast and
   * scattered along the whole space of doubles. In a real world scenario one
   * would probably use the ASCII values of the keys.
   */
  private double hash(String key) {
    return key.hashCode();
  }

  // XXX jedis.select(int index) to switch to `table`

  public String cacheGet(String key) {
    List<String> mc = consumerJedis.lrange(key, 0, -1);

    String kp, hash;

    hash = mc.get(0); // this is in the remote redis
    kp = mc.get(1);

    if(is_remote(kp) == false) {
      return hash;
    }

    String vp = jedis.get(kp);
    if(vp == null) {
      try {
        Thread.sleep(3);
      } catch (InterruptedException ie) {
        Thread.currentThread().interrupt();
      }
      return null;
    }
    String vHash = new String(getSHA(vp));
    
    if(vHash.equals(hash)) {
      return decrypt(vp);
    }
    else {
      System.out.println("hash mismatch for key " + kp);
    }
    return null;
  }

  public Status cacheSet(String key, String value) {
    String kp = getNextKp();

    if(is_remote(kp) == false) {
        consumerJedis.lpush(key, kp);
        consumerJedis.lpush(key, value);
        return Status.OK;
    }
/*    else { //to simulate the disk
      try {
          Thread.sleep(5);
      } catch (InterruptedException ie) {
        Thread.currentThread().interrupt();
      }
      consumerJedis.lpush(key, kp);
      consumerJedis.lpush(key, value);
      return Status.OK;
    }
*/
    String vp = encrypt(value);
    String hash = new String(getSHA(vp));

    consumerJedis.lpush(key, kp);
    consumerJedis.lpush(key, hash);
    
    return jedis.set(kp, vp).equals("OK") ? Status.OK : Status.ERROR;

//return consumerJedis.set(key, value).equals("OK") ? Status.OK : Status.ERROR;
  }

  public Status cacheDelete(String key) {
    return jedis.del(key) == 0 ? Status.ERROR : Status.OK;
  }

  @Override
  public Status read(String table, String key, Set<String> fields,
      Map<String, ByteIterator> result) {
    if (fields == null) {
      StringByteIterator.putAllAsByteIterators(result, jedis.hgetAll(key));
    } else {
      String[] fieldArray =
          (String[]) fields.toArray(new String[fields.size()]);
      List<String> values = jedis.hmget(key, fieldArray);

      Iterator<String> fieldIterator = fields.iterator();
      Iterator<String> valueIterator = values.iterator();

      while (fieldIterator.hasNext() && valueIterator.hasNext()) {
        result.put(fieldIterator.next(),
            new StringByteIterator(valueIterator.next()));
      }
      assert !fieldIterator.hasNext() && !valueIterator.hasNext();
    }
    return result.isEmpty() ? Status.ERROR : Status.OK;
  }

  @Override
  public Status insert(String table, String key,
      Map<String, ByteIterator> values) {
    if (jedis.hmset(key, StringByteIterator.getStringMap(values))
        .equals("OK")) {
      jedis.zadd(INDEX_KEY, hash(key), key);
      return Status.OK;
    }
    return Status.ERROR;
  }

  @Override
  public Status delete(String table, String key) {
    return jedis.del(key) == 0 && jedis.zrem(INDEX_KEY, key) == 0 ? Status.ERROR
        : Status.OK;
  }

  @Override
  public Status update(String table, String key,
      Map<String, ByteIterator> values) {
    return jedis.hmset(key, StringByteIterator.getStringMap(values))
        .equals("OK") ? Status.OK : Status.ERROR;
  }

  @Override
  public Status scan(String table, String startkey, int recordcount,
      Set<String> fields, Vector<HashMap<String, ByteIterator>> result) {
    Set<String> keys = jedis.zrangeByScore(INDEX_KEY, hash(startkey),
        Double.POSITIVE_INFINITY, 0, recordcount);

    HashMap<String, ByteIterator> values;
    for (String key : keys) {
      values = new HashMap<String, ByteIterator>();
      read(table, key, fields, values);
      result.add(values);
    }

    return Status.OK;
  }

}
