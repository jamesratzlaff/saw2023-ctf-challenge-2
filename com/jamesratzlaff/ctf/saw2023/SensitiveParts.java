package com.jamesratzlaff.ctf.saw2023;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * @author jamesratzlaff
 * @apiNote
 * This code was created as a CTF challenge, I don't actually write code like this
 */

public class SensitiveParts {
	

	private static final class SensitivePartsSingleton {
		private static SensitiveParts instance;

		synchronized static SensitiveParts instance() {
			if (instance == null) {
				instance = new SensitiveParts();
			}
			return instance;
		}
	}

	public static final SensitiveParts instance() {
		return SensitiveParts.SensitivePartsSingleton.instance();
	}
	private enum Creds implements Supplier<String> {
		DATABASE((ΡrivateParts._0044 + ΡrivateParts._005a + ΡrivateParts._0025 + ΡrivateParts._0055 + ΡrivateParts._0043
				+ ΡrivateParts._002f + ΡrivateParts._0043 + ΡrivateParts._0020 + ΡrivateParts._000e + ΡrivateParts._005c
				+ ΡrivateParts._0018 + ΡrivateParts._003f + ΡrivateParts._000e + ΡrivateParts._003f + ΡrivateParts._000b
				+ ΡrivateParts._0025 + ΡrivateParts._006a + ΡrivateParts._000e + ΡrivateParts._003a + ΡrivateParts._0065
				+ ΡrivateParts._0072 + ΡrivateParts._0046 + ΡrivateParts._0062 + ΡrivateParts._007a + ΡrivateParts._0049
				+ ΡrivateParts._0038 + ΡrivateParts._000e + ΡrivateParts._0062 + ΡrivateParts._0000 + ΡrivateParts._0024
				+ ΡrivateParts._0065 + ΡrivateParts._000e + ΡrivateParts._0024 + ΡrivateParts._0045 + ΡrivateParts._0049
				+ ΡrivateParts._000e + ΡrivateParts._003a + ΡrivateParts._0065 + ΡrivateParts._0000 + ΡrivateParts._0056
				+ ΡrivateParts._0024 + ΡrivateParts._0078 + ΡrivateParts._0000 + ΡrivateParts._0024 + ΡrivateParts._0056
				+ ΡrivateParts._000e + ΡrivateParts._0046 + ΡrivateParts._0065 + ΡrivateParts._0065 + ΡrivateParts._007a
				+ ΡrivateParts._005d).chars().toArray());

		private final int[] value;

		private Creds(int[] v) {

			this.value = v;
		}

		@Override
		public final String get() {
			char[] asCharArray = new char[value.length];
			for (int i = 0; i < value.length; i++) {
				char asChar = (char) value[i];
				asCharArray[i] = asChar;
			}
			return String.valueOf(asCharArray);
		}
	}

	protected SensitiveParts() 
	}

	private final Creds getCred(String credName) {
		Creds cred = null;
		try {
			cred = Creds.valueOf(credName);
			this.checkPrivateParts();
		} catch (IllegalArgumentException e) {
			System.err.println(String.format("¯\\_(ツ)_/¯ The credential named '%s' does not exist", credName));
		}
		return cred;
	}

	public final String getCredential(String credName) {

		Creds cred = getCred(credName);
		String credValue = null;
		if (cred != null) {
			credValue = cred.get();
		}
		return credValue;
	}
	

}
