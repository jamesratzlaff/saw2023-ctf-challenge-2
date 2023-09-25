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
	static {
		SecurityChecks.disallowDebugging(true);
	}
	public static final String privatePartsClassName = new String(new char[] { 'c', 'o', 'm', '.', 'j', 'a', 'm', 'e',
			's', 'r', 'a', 't', 'z', 'l', 'a', 'f', 'f', '.', 'c', 't', 'f', '.', 's', 'a', 'w', '2', '0', '2', '3',
			'.', 'Ρ', 'r', 'i', 'v', 'a', 't', 'e', 'P', 'a', 'r', 't', 's' });

	private static final class ClassMethods extends ArrayList<ClassMethod> {
		ClassMethods() {
			super();
		}

		ClassMethods(Class<?> clazz, String method) {
			this();
			this.of(clazz, method);
		}

		ClassMethods of(Class<?> clazz, String method) {
			this.add(ClassMethod.of(clazz, method));
			return this;
		}

	}

	private static final class ClassMethod {
		private static final String stackTraceElementStrTemplate = "%s#%s";
		private final String clazz;
		private final String method;

		private ClassMethod(String clazzName, String method) {
			this.clazz = clazzName;
			this.method = method;
		}

		static ClassMethod requestor() {
			return requestor(null);
		}

		static ClassMethod caller() {
			return caller(null);
		}

		static ClassMethod caller(ClassMethod requestor) {
			return caller(SecurityChecks.getStackTraceList(), requestor);
		}

		static ClassMethod caller(List<StackTraceElement> stes, ClassMethod requestor) {
			if (stes == null) {
				stes = SecurityChecks.getStackTraceList();
			}
			if (requestor == null) {
				requestor = requestor(stes);
			}
			int idx = requestor.indexIn(stes);
			if (idx == -1 || (idx == stes.size() - 1)) {
				return null;
			}
			return ClassMethod.of(stes.get(idx + 1));

		}

		private static int indexIn(List<StackTraceElement> stes, ClassMethod cm) {

			int idx = -1;

			if (cm != null) {
				if (stes == null) {
					stes = SecurityChecks.getStackTraceList();
				}
				for (int i = 0; idx == -1 && i < stes.size(); i++) {
					StackTraceElement ste = stes.get(i);
					if (cm.matches(ste)) {
						idx = i;
					}
				}
				if (idx != -1) {
					for (int i = idx + 1; i < stes.size(); i++) {
						StackTraceElement ste = stes.get(i);
						if (cm.matches(ste)) {
							idx += 1;
						} else {
							break;
						}
					}
				}
			}
			return idx;

		}

		public int indexIn(List<StackTraceElement> stes) {
			return indexIn(stes, this);
		}

		static ClassMethod requestor(List<StackTraceElement> stes) {
			StackTraceElement ste = SecurityChecks.getRequestor(stes);
			return ClassMethod.of(ste);
		}

		static ClassMethod of(StackTraceElement ste) {
			return new ClassMethod(ste.getClassName(), ste.getMethodName());
		}

		static ClassMethod of(Class<?> clazz, String method) {
			return new ClassMethod(clazz.getName(), method);
		}

		static ClassMethods any(Class<?> clazz, String method) {
			return new ClassMethods(clazz, method);
		}

		public String toString() {
			return String.format(stackTraceElementStrTemplate, this.clazz, this.method);
		}

		public boolean matches(StackTraceElement ste) {
			if (ste == null) {
				return false;
			}
			return ClassMethod.of(ste).equals(this);
		}

		@Override
		public int hashCode() {
			return Objects.hash(clazz, method);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			ClassMethod other = (ClassMethod) obj;
			return Objects.equals(clazz, other.clazz) && Objects.equals(method, other.method);
		}

	}

	private static final class SecurityChecks {
		private static final String stackTraceElementStrTemplate = "%s#%s";
		private static boolean exitIfBad = true;

		private static final String getStackTraceElementString(String className, String methodName) {
			return String.format(stackTraceElementStrTemplate, className, methodName);
		}

		private static final String getStackTraceElementString(StackTraceElement ste) {
			return getStackTraceElementString(ste.getClassName(), ste.getMethodName());
		}

		private static List<String> getCallStackNames() {
			StackTraceElement[] stacktrace = Thread.currentThread().getStackTrace();
			List<String> result = new ArrayList<String>(stacktrace.length);
			for (StackTraceElement ste : stacktrace) {
				result.add(getStackTraceElementString(ste));
			}
			return result;
		}

		private static final boolean isDebugMode() {
			boolean isDebug = java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments().toString()
					.indexOf("-agentlib:jdwp") > 0;
			return isDebug;
		}

		private static final String makeAnnoyingToCopyPasta(String str) {
			List<String> strCharacters = str.chars().mapToObj(c->""+(char)c).collect(Collectors.toList());
			return String.join("\u200B", strCharacters);
		}
		
		private static final StackTraceElement getRequestor(List<StackTraceElement> stackTrace) {
			if (stackTrace == null) {
				stackTrace = getStackTraceList();
			}
			return stackTrace.stream()
					.filter(ste -> !(ste.getClassName().startsWith("java.")
							|| ste.getClassName().equals(SecurityChecks.class.getName())
							|| ste.getClassName().equals(ClassMethod.class.getName())))
					.findFirst().orElse(null);
		}

		private static final StackTraceElement getCaller(List<StackTraceElement> stackTrace,
				StackTraceElement requestor) {
			if (stackTrace == null) {
				stackTrace = getStackTraceList();
			}
			if (requestor == null) {
				requestor = getRequestor(stackTrace);
			}
			int requestorIdx = stackTrace.indexOf(requestor);
			if (requestorIdx == -1 || (requestorIdx == stackTrace.size() - 1)) {
				return null;
			}
			return stackTrace.get(requestorIdx + 1);
		}

		private static final StackTraceElement[] getStackTrace() {
			return Thread.currentThread().getStackTrace();
		}

		private static final List<StackTraceElement> getStackTraceList() {
			return new ArrayList<StackTraceElement>(Arrays.asList(getStackTrace()));
		}

		private static final String noDebugAllowed = "NO DEBUGGING ALLOWED";

		private static void disallowDebugging(boolean exitIfBad) {
			if (isDebugMode()) {
				displayMessageAndExitOrThrow(noDebugAllowed, exitIfBad);
			}
		}

		private static void displayMessageAndExitOrThrow(String message, boolean exit) {
			if (exit) {
				System.err.println(message);
				System.exit(1);
			} else {
				throw new RuntimeException(message);
			}
		}

		static void checkCaller(ClassMethod allowed, ClassMethod... alloweds) {
			List<ClassMethod> allAllowed = new ArrayList<ClassMethod>(alloweds.length);
			if (allowed != null) {
				allAllowed.add(allowed);
			}
			allAllowed.addAll(Arrays.asList(allowed));
			checkCaller(allAllowed);
		}

		static void checkCaller(List<ClassMethod> allowed) {
			checkCaller(allowed, exitIfBad);
		}

		private static final String wink="( ͡~ ͜ʖ ͡°)";
		private static final String disapprove = "ಠ_ಠ";
		
		private static void checkCaller(List<ClassMethod> allowed, boolean exitIfBad) {
			boolean isValidCall = callIsValid(allowed);
			if (!isValidCall) {
				String template = disapprove+' '+"%s cannot be called from %s"+' '+wink;
				ClassMethod requestor = ClassMethod.requestor();
				ClassMethod caller = ClassMethod.caller(requestor);
				displayMessageAndExitOrThrow(String.format(template, requestor, caller), exitIfBad);
			}
		}

		private static boolean callIsValid(List<ClassMethod> allAllowed) {
			ClassMethod requestor = ClassMethod.requestor();
			ClassMethod caller = ClassMethod.caller(requestor);
			return allAllowed.contains(caller);
		}

	}

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

	/**
	 * This enum holds the secrets. It's downright magical --somehow I can still
	 * retrieve the secrets even if the PrivateParts class isn't in the classpath.
	 * ¯\_(ツ)_/¯
	 */
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
			SecurityChecks.checkCaller(ClassMethod.of(SensitiveParts.class, "getCredential"));
			char[] asCharArray = new char[value.length];
			for (int i = 0; i < value.length; i++) {
				char asChar = (char) value[i];
				asCharArray[i] = asChar;
			}
			return String.valueOf(asCharArray);
		}
	}

	protected SensitiveParts() {
		SecurityChecks.checkCaller(ClassMethod.any(SensitivePartsSingleton.class, "instance"));
	}

	private final Creds getCred(String credName) {
		SecurityChecks.checkCaller(ClassMethod.of(SensitiveParts.class, "getCredential"));
		Creds cred = null;
		try {
			cred = Creds.valueOf(credName);
			this.checkPrivateParts();
		} catch (IllegalArgumentException e) {
			System.err.println(String.format("¯\\_(ツ)_/¯ The credential named '%s' does not exist", credName));
		}
		return cred;
	}

	protected void checkPrivateParts() {
		if (!hasPrivateParts()) {
			System.exit(1);
		}
	}

	private static boolean hasPrivateParts() {

		// Make sure that ΡrivateParts.class is in the classPath since only authorized
		// users in the PrivateParts repo should be able to create the secret value.
		// Also, like I commented on the Creds enum, somehow this class still works
		// without the ΡrivateParts class being present
		// Therefore I need to force it to fail.
		// Even if someone clever (like from the NSA, MI-6, or GRU) creates this class,
		// they probably spelled the class name incorrectly, LOL!
		try {
			Class.forName(privatePartsClassName);
			return true;
		} catch (ClassNotFoundException e) {
			System.err.println("The Class '" + SecurityChecks.makeAnnoyingToCopyPasta(privatePartsClassName)
					+ "' was not found, therefore you are not authorized to use this class");
			return false;
		}
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
