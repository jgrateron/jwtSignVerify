package com.fresco;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class App {
	public static void main(String[] args) throws IOException, JOSEException, ParseException {
		Gson gson = new Gson();
		Type listType = new TypeToken<List<String>>() {
		}.getType();
		String content = new String(Files.readAllBytes(Paths.get("src/main/resources/emails.json")));
		List<String> emails = gson.fromJson(content, listType);
		int i = 1, idx = 0;
		String jwtSecret = System.getenv("JWT_SECRET");
		int numIterations = Integer.parseInt(args[0]);
		long startTS = 0;

		var signer = new MACSigner(jwtSecret.getBytes());
		while (true) {
			if (i == 10000) {
				startTS = System.currentTimeMillis();
			}
			String email = emails.get(idx);
			long currTS = System.currentTimeMillis();

			// Prepare JWT with claims set
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()//
					.subject(email)//
					.issueTime(new Date(currTS))//
					.expirationTime(new Date(currTS + 2 * 60 * 60 * 1000))//
					.build();

			SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

			// Apply the HMAC protection
			signedJWT.sign(signer);

			// Serialize to compact form, produces something like
			String s = signedJWT.serialize();

			signedJWT = SignedJWT.parse(s);
			
			var verifier = new MACVerifier(jwtSecret.getBytes());
			if (!signedJWT.verify(verifier)) {
				System.exit(1);
			}
			
			if (!signedJWT.getJWTClaimsSet().getSubject().equals(email)) {
				System.exit(1);
			}
			
			idx++;
			if (idx >= emails.size()) {
				idx = 0;
			}
			if (i++ > numIterations) {
				break;
			}
		}
		long endTS = System.currentTimeMillis();
		long diff = endTS - startTS;
		System.out.println(diff);
	}
}
