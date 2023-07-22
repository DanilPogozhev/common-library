package de.pogozhev.common.mfa;

public interface MFAGenerator {
    String generate(String privateKey);
}
