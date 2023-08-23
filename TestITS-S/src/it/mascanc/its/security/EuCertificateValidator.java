package it.mascanc.its.security;

import java.nio.file.*;
import java.util.Map;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.FullCtl;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.FullCtl;

/**
 * Verify CAM messages with EU Root Certificate.
 * 
 * @author Merlin Chlosta
 */

public class EuCertificateValidator {
	// https://stackoverflow.com/a/140861
	/* s must be an even-length string. */
	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
								 + Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

	public EuCertificateValidator() throws Exception {
		// EU Root Certificate
		Path path = Paths.get("/home/merlin/TestITS-S/TestITS-S/./src/it/mascanc/its/security/D875151DE8A41EBD");
		EtsiTs103097Certificate rootCACertificate;
		try {
			rootCACertificate = new EtsiTs103097Certificate(Files.readAllBytes(path));
		} catch (Exception e) {
			System.out.println("Error reading RootCACertificate: " +e);
			rootCACertificate = null;
		}

		System.out.println("EU ROOT CERT");
		System.out.println(rootCACertificate.toString());
		System.out.println("#########################################################################");

		// Wireshark field: ieee1609dot2.Ieee1609Dot2Data_element (copy as hex stream)
		byte[] signedDataBytes = hexStringToByteArray("0381004003805620500280003201001400a6daf37248b48c9be80d1eb14ab10570fc0f821c0ad00000a00007d100000202f37248b4ea00005a8ac678ce175997623022c6de3e239658ad00e0defe02c68a3f33f401ffba203fff945980400124000228ed410a3c558041d7a5daf37248b48083b53a81b2665d7cac98995b6b8eae3a3ffa84fa874cccf4771fc573f6c1b0c607cf8afc7595671d8286b8f4f61e11c138a99b10fc1b027ec6e8a5db6ff05f70f4");
		EtsiTs103097DataSigned signedDataContainer;
		try {
			signedDataContainer = new EtsiTs103097DataSigned(signedDataBytes);
		} catch (Exception e) {
			System.out.println("Error reading Signed Data: " +e);
			throw e;
		}
		System.out.println("SIGNED DATA");
		System.out.println(signedDataContainer.toString());
		System.out.println("#########################################################################");
	
		// Wireshark field: ieee1609dot2.Certificate_element  (copy as hex stream)
		byte[] signerCertificateBytes = hexStringToByteArray("800300800498fbf3b8b8c2491083000000000024382fb58400a8010280012481040301000080012581050401901a25808083f1bddd238a1365a471fe4cbf7c2cba809418a4adefd32c490b43747f6ac574bd80800bd79c6d023bc6a34a8c4cc56c28ce53a672657303bb70eb4079e7132a3c729bf0babbcbb7923401ec2f0b23a104630bda2461aa992c663121f0b9d94a853148");
		EtsiTs103097Certificate signerCertificate;

		try {
			signerCertificate = new EtsiTs103097Certificate(signerCertificateBytes);
		} catch (Exception e) {
			System.out.println("Error reading Signer Certificate: " +e);
			throw e;
		}

		System.out.println("SIGNER CERT");
		System.out.println(signerCertificate.toString());
		System.out.println("#########################################################################");

		DefaultCryptoManager cryptoManager = new DefaultCryptoManager();
		cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

		SignedData signedData = (SignedData) signedDataContainer.getContent().getValue();

		System.out.println("Verifiying Data Integrity (with Signer certificate)");
		Boolean b = cryptoManager.verifySignature(signedData.getTbsData().getEncoded(), signedData.getSignature(), signerCertificate);
		System.out.println("Data integrity: " +(b ? "valid" : "invalid"));

		System.out.println("Verifiying Signer Cert with Root CA Certificate.");
		System.out.println("TODO: not implemented :)");
		/* 
		System.out.print("Verifiying Signer Cert. TODO: not implemented :)");
		// TODO: not really implemented now, would require fetching + validating the certificate chain?
		Boolean certValid = cryptoManager.verifyCertificate(signerCertificate, rootCACertificate);
		System.out.println("Signer Cert: " + (certValid ? "valid": "invalid"));
		System.out.println("#########################################################################"); */
	}
}
