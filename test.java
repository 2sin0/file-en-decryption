import java.util.Scanner;

public class test{
	public static void main(String args[]) throws Exception
	{
		Scanner scanner = new Scanner(System.in);
		
		byte[] salt = new byte[]{0x78, 0x57, (byte)0x8e, 0x5a, 0x5d, 0x63, (byte)0xcb, 0x06};
		
		
		String path = "       ";			//source 경로
		String o_path = "       ";	  //암호화 후 저장경로
		String outputpath = "       "; //o_path에 저장된 파일 복호화 후 저장경로
		
		System.out.println("password를 설정해주세요");
		String password = scanner.next();
		
		byte []derivedkey = tools.PBKDF1(password, salt);
		byte []password_check = tools.hash(derivedkey, salt); //password_check를 outputstream 객체에 넣어야함
		tools.fileEnc(derivedkey, path, o_path);
		
		System.out.println("password를 입력해주세요");
		String password2 = scanner.next();
		
		byte []derivedkey2 = tools.PBKDF1(password2, salt);
		byte []password_check2 = tools.hash(derivedkey2, salt);
		if(java.util.Arrays.equals(password_check, password_check2)) {
		tools.fileDec(derivedkey, o_path, outputpath);
		}
		else {
			System.out.println("잘못된 password입니다.");
		}
		scanner.close();
	}
}

