import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class tools{
	public static byte[] hash(byte[]derivedkey, byte[]salt) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		
		MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
		byte temp [] = new byte[derivedkey.length + salt.length];
		System.arraycopy(derivedkey, 0, temp, 0, derivedkey.length);
		System.arraycopy(salt, 0, temp, derivedkey.length, salt.length);
		hash.update(temp);
		return temp;
	}
	
	
	public static byte[] PBKDF1(String password, byte[]salt) throws Exception {
			Security.addProvider(new BouncyCastleProvider());
			
			MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
																	//input값
			
			byte[] p = utils.toByteArray(password);	
			int iteration = 1000;
			int dkLen = 16;
			
			
			byte[] input = new byte[p.length + salt.length];										// p와 s concat 후  update
			System.arraycopy(p, 0, input, 0, p.length);
			System.arraycopy(salt, 0, input, p.length, salt.length);
			hash.update(input);
			
			for(int i=0; i<iteration-1; i++) {
				byte temp[] = hash.digest();
				hash.update(temp);
			}
			byte [] output = hash.digest();
			byte [] result = new byte[16];
			System.arraycopy(output, 0, result, 0,dkLen);
			return result;
			//dkLen길이로 자르고 리턴
	
	}

	public static void fileEnc(byte[] derivedKey, String path, String o_path) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		
		byte[] ivBytes = new byte[] {0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0x03,
				0x02, 0x01, 0x00};
		
		SecretKeySpec key = new SecretKeySpec(derivedKey, "AES");
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		
		Cipher cipher = null;

		cipher =  Cipher.getInstance("AES/CBC/PKCS7Padding", "BC"); 
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		File file = new File(path);
		int fileSize = (int) file.length();
		
		int BUF_SIZE = 1024;
		byte[] buffer = new byte[BUF_SIZE];
		   
		FileInputStream fis = new FileInputStream(path);
		FileOutputStream fo = new FileOutputStream(o_path);
		int read = BUF_SIZE;
		   
		int count = 0;							
		 
		while ((read = fis.read(buffer, 0, BUF_SIZE)) == BUF_SIZE) {					
			   fo.write(cipher.update(buffer,0,read));
			   			   count = count+1;
			   if(count*BUF_SIZE/fileSize<1) {												//암호화 진행상황 계산
				   System.out.println("Encrypting : " +100*count*BUF_SIZE/fileSize+"%");
			   }
		   }
		fo.write(cipher.doFinal(buffer,0,read));
		System.out.println("Encrypting : 100%");
		  
		fis.close();
		fo.close();
	}

	public static void fileDec(byte[] derivedKey, String path, String o_path) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		
		byte[] ivBytes = new byte[] {0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0x03,
				0x02, 0x01, 0x00};
		
		SecretKeySpec key = new SecretKeySpec(derivedKey, "AES"); 
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		
		Cipher cipher = null;

		cipher =  Cipher.getInstance("AES/CBC/PKCS7Padding", "BC"); 
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
				
		int BUF_SIZE = 1024;
		FileInputStream fis1 = new FileInputStream(path);
		FileOutputStream fo1 = new FileOutputStream(o_path);
		byte[] buffer1 = new byte[BUF_SIZE];
		int read1 = BUF_SIZE;
		int count=0;
		File file = new File(path);
		int fileSize = (int) file.length();
		while ((read1 = fis1.read(buffer1, 0, BUF_SIZE)) == BUF_SIZE) {				
			   fo1.write(cipher.update(buffer1, 0, read1));
			   count = count+1;
			   if(count*BUF_SIZE/fileSize<1) {												//복호화 진행상황 계산
				   System.out.println("Decrypting : " +100*count*BUF_SIZE/fileSize+"%");
			   }
			   						   }
		fo1.write(cipher.doFinal(buffer1, 0, read1));			
		System.out.println("Decrypting : 100%"); 
		 
		fis1.close();
		fo1.close();
	}
}	
	


