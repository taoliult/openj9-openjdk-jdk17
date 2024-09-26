/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2024, 2024 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */

 /*
 * @test
 * @summary Test Provider Properties
 * @library /test/lib
 * @run junit TestProperties
 */

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
  
import java.security.Provider;
import java.security.Security;
  
import java.util.stream.Stream;
  
import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;
  
public class TestProperties {
  
    //  private static Stream<Arguments> patternMatches_expectedExitValue0() {
    //      return Stream.of(
    //              // Test OpenJCEPlusFIPS strict profile provider list
    //              Arguments.of("OpenJCEPlusFIPS.FIPS140-3",
    //                      System.getProperty("test.src") + "/provider-java.security",
    //                      "(?s)(?=.*OpenJCEPlusFIPS)(?=.*\\bSUN\\b)(?=.*SunJSSE)")
    //      );
    //  }
 
    private static Stream<Arguments> patternMatches_expectedExitValue1() {
        return Stream.of(
                // Test base profile - misspell properties
                Arguments.of("Test-Profile.Base",
                        System.getProperty("test.src") + "/property-java.security",
                        " The property names: RestrictedSecurity.Test-Profile.Base.tls.disabledAlgorithmsWrongTypo " +
                                "in profile RestrictedSecurity.Test-Profile.Base \\(or a base profile\\) are not recognized"),
                // Test extended profile - misspell properties
                Arguments.of("Test-Profile.Extended_1",
                        System.getProperty("test.src") + "/property-java.security",
                        "The property names: RestrictedSecurity.Test-Profile.Extended_1.desc.nameWrongTypo, " +
                                "RestrictedSecurity.Test-Profile.Extended_1.jce.providerWrongTypo.3 in profile " +
                                "RestrictedSecurity.Test-Profile.Extended_1 \\(or a base profile\\) are not recognized"),
                // Test extended profile from another extended profile - misspell properties
                Arguments.of("Test-Profile.Extended_2",
                        System.getProperty("test.src") + "/property-java.security",
                        "The property names: RestrictedSecurity.Test-Profile.Extended_2.jce.providerWrongTypo.13 " +
                                "in profile RestrictedSecurity.Test-Profile.Extended_2 \\(or a base profile\\) are not recognized"),
                // Test profile - profile not exist
                Arguments.of("Test-Profile.NotExist",
                        System.getProperty("test.src") + "/property-java.security",
                        "Test-Profile.NotExist is not present in the java.security file."),
                // Test profile - multi default profile
                Arguments.of("Test-Profile.MultiDefault",
                        System.getProperty("test.src") + "/property-java.security",
                        "Multiple default RestrictedSecurity profiles for Test-Profile.MultiDefault"),
                // Test profile - no default profile
                Arguments.of("Test-Profile.NoDefault",
                        System.getProperty("test.src") + "/property-java.security",
                        "No default RestrictedSecurity profile was found for Test-Profile.NoDefault"),
                // Test extended profile - base profile not exist
                Arguments.of("Test-Profile.Extended_3",
                        System.getProperty("test.src") + "/property-java.security",
                        "Test-Profile.Extended_3 that is supposed to extend Test-Profile.BaseNotExist is not present " +
                                "in the java.security file or any appended files"),
                // Test extended profile - base profile not full profile name
                Arguments.of("Test-Profile.Extended_4",
                        System.getProperty("test.src") + "/property-java.security",
                        "Test-Profile.Extended_4 that is supposed to extend BaseNotFullProfileName is not a full profile name"),
                // Test profile - base profile without hash value
                Arguments.of("Test-Profile.BaseWithoutHash",
                        System.getProperty("test.src") + "/property-java.security",
                        "Test-Profile.BaseWithoutHash is a base profile, so a hash value is mandatory"),
                // Test profile - incorrect definition of hash value
                Arguments.of("Test-Profile.Hash_1",
                        System.getProperty("test.src") + "/property-java.security",
                        "Incorrect definition of hash value for Test-Profile.Hash_1"),
                // Test profile - incorrect hash value
                Arguments.of("Test-Profile.Hash_2",
                        System.getProperty("test.src") + "/property-java.security",
                        "Hex produced from profile is not the same is a base profile, so a hash value is mandatory"),
                // Test property not appendable
                Arguments.of("Test-Profile.SetProperty_1",
                        System.getProperty("test.src") + "/property-java.security",
                        "Property jdkSecureRandomProvider is not appendable"),
                // Test property does not exist in parent profile, cannot append
                Arguments.of("Test-Profile.SetProperty_2",
                        System.getProperty("test.src") + "/property-java.security",
                        "Property jdkTlsDisabledNamedCurves does not exist in parent profile. Cannot append"),
                // Test property does not exist in parent profile, cannot remove
                Arguments.of("Test-Profile.SetProperty_3",
                        System.getProperty("test.src") + "/property-java.security",
                        "Property jdkTlsLegacyAlgorithms does not exist in parent profile. Cannot remove"),
                // Test property value is not in existing values
                Arguments.of("Test-Profile.SetProperty_4",
                        System.getProperty("test.src") + "/property-java.security",
                        "Value TestDisabledlgorithms is not in existing values")
        );
    }
  
    //  @ParameterizedTest
    //  @MethodSource("patternMatches_expectedExitValue0")
    //  public void shouldContain_expectedExitValue0(String customprofile, String securityPropertyFile, String expected) throws Exception {
    //      OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
    //              "-Dsemeru.fips=true", 
    //              "-Dsemeru.customprofile=" + customprofile,
    //              "-Djava.security.properties=" + securityPropertyFile,
    //              //"-Djava.security.debug=semerufips", 
    //              "TestProperties"
    //      );
    //      outputAnalyzer.reportDiagnosticSummary();
    //      outputAnalyzer.shouldHaveExitValue(0).shouldMatch(expected);
    //  }
 
    @ParameterizedTest
    @MethodSource("patternMatches_expectedExitValue1")
    public void shouldContain_expectedExitValue1(String customprofile, String securityPropertyFile, String expected) throws Exception {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                "-Dsemeru.fips=true", 
                "-Dsemeru.customprofile=" + customprofile,
                "-Djava.security.properties=" + securityPropertyFile,
                //"-Djava.security.debug=semerufips", 
                "TestProperties"
        );
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(1).shouldMatch(expected);
    }
  
    public static void main(String[] args) throws Exception {
        // Something to trigger "properties" debug output
        try {
            Provider p[] = Security.getProviders();
            for (int i = 0; i < p.length; i++) {
                System.out.println("Provider Name: " + p[i].getName());
                System.out.println("Provider Version: " + p[i].getVersion());
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}