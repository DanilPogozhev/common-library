package de.pogozhev.common.mfa;

public abstract class MFAGeneratorFactory {

    public static MFAGenerator create(MFAGeneratorType type) {
        switch (type) {
            case TIME_BASED_ONE_TIME_PASSWORD -> {
                return new TotpGeneratorImpl();
            }
        }
        return new TotpGeneratorImpl();
    }
}
