/*
 * Author: Singh Addaputha
 * 
 *  Perform TS cleanup. Remove expired CA certificates.
 *  May 16, 2023
 *  
 */
package com.cnb.util;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;

public class TSCheck {  
	
	private static final String HEADER = "-----BEGIN CERTIFICATE-----\n";
	private static final String TRAILER = "-----END CERTIFICATE-----\n";
	
	public static void main(String[] args) {         

		String pemFilePath = args[0];
		String b64FilePath = pemFilePath + ".b64";
		
		System.out.println("Reading TrustStore: " + pemFilePath);
		
		try {             
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());             
			FileReader fr = new FileReader(pemFilePath);             
			PEMParser pemParser = new PEMParser(fr);             
			Object pemObject;             
			
			StringWriter sw = new StringWriter();
			
			while ((pemObject = pemParser.readObject()) != null) {            
				
				if (pemObject instanceof X509CertificateHolder) {                     
					
					X509CertificateHolder certificateHolder = (X509CertificateHolder) pemObject;                     
					X509Certificate certificate = convertToX509Certificate(certificateHolder);    
					String subject = certificate.getSubjectX500Principal().getName();
					
					String validity = "[" + certificate.getNotBefore().toGMTString() + 
							", " + certificate.getNotAfter().toGMTString() +
							"]";
					
					try {
						certificate.checkValidity();
						write(sw,Base64.getEncoder().encodeToString(certificate.getEncoded()),subject);
						System.out.println(validity+"\n");
					} catch(Exception e) {
						System.out.println("Certificate Subject: " + 
						certificate.getSubjectX500Principal().getName() +
						" is invalid!");
					}
					
				}             
			}
			
			pemParser.close();
			writeFile(pemFilePath,sw.toString());
			writeFile(b64FilePath,Base64.getEncoder().encodeToString(sw.toString().getBytes()));
			sw.close();
			
		} catch (Exception e) {             
				e.printStackTrace();
		}
	}
	
	private static void writeFile(String filePath, String contents) {
		
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(filePath));
			bw.write(contents);
			bw.close();
		} catch(IOException ioe) {
			ioe.printStackTrace();
		}
		
	}

	private static void write(StringWriter sw, String pemStr,String subject) {
		
		String s = sw.toString();

		try {
			sw.append(HEADER);
			
			int len = pemStr.length();
			int offset = 0;
			
			while(offset < len) {
				int endIdx = Math.min(offset + 64, len);
				sw.write(pemStr,offset,endIdx-offset);
				sw.write("\n");
				offset = endIdx;
			}
			
			sw.write(TRAILER);
			System.out.println("Processed <" + subject + ">");
			
		} catch(Exception e) {
			sw = new StringWriter();
			sw.write(s);
			System.out.println("Error processing " + subject);
			e.printStackTrace();
		}
		
	}

	private static X509Certificate convertToX509Certificate(X509CertificateHolder certificateHolder)             
			throws CertificateException, CertificateEncodingException, IOException {
		
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");       
		
		return (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificateHolder.getEncoded()));     
		
	}
}
