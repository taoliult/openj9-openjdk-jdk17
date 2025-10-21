/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2024, 2025 All Rights Reserved
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
 * @summary Test Restricted Security Mode Policy Sunset
 * @library /test/lib
 * @run junit TestPolicySunset
 */

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.Provider;
import java.security.Security;

import java.util.stream.Stream;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

public class TestPolicySunset {

    private static Stream<Arguments> patternMatches_expectedExitValue0() {
        return Stream.of(
                // 1 - Test property - policy sunset but ignore sunset expiration
                // and not supress sunset warning.
                Arguments.of("Test-Profile-PolicySunset.Base",
                        System.getProperty("test.src") + "/property-java.security",
                        false, true, 
                        "Restricted security policy has expired")
        );
    }

    private static Stream<Arguments> patternMatches_expectedExitValue1() {
        return Stream.of(
                // 1 - Test property - policy sunset.
                Arguments.of("Test-Profile-PolicySunset.Base",
                        System.getProperty("test.src") + "/property-java.security",
                        false, false,
                        "Restricted security policy has expired"),
                
                //         // 2 - Test property - policy sunset format.
                // Arguments.of("Test-Profile-PolicySunsetFormat.Base",
                //         System.getProperty("test.src") + "/property-java.security",
                //         "Restricted security policy sunset date is incorrect, the correct format is yyyy-MM-dd")
        );
    }

    @ParameterizedTest
    @MethodSource("patternMatches_expectedExitValue0")
    public void shouldContain_expectedExitValue0(String customprofile, String securityPropertyFile, String supresssunsetwarning, String ignoresunsetexpiration, String expected) throws Exception {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                jvmOptions,
                "-Dsemeru.fips=true",
                "-Dsemeru.customprofile=" + customprofile,
                "-Djava.security.properties=" + securityPropertyFile,
                "-Dsemeru.restrictedsecurity.supresssunsetwarning=" + supresssunsetwarning,
                "-Dsemeru.restrictedsecurity.ignoresunsetexpiration=" + ignoresunsetexpiration,
                "TestProperties"
        );
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(0).shouldMatch(expected);
    }

    @ParameterizedTest
    @MethodSource("patternMatches_expectedExitValue1")
    public void shouldContain_expectedExitValue1(String customprofile, String securityPropertyFile, String supresssunsetwarning, String ignoresunsetexpiration, String expected) throws Exception {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                "-Dsemeru.fips=true",
                "-Dsemeru.customprofile=" + customprofile,
                "-Djava.security.properties=" + securityPropertyFile,
                "-Dsemeru.restrictedsecurity.supresssunsetwarning=" + supresssunsetwarning,
                "-Dsemeru.restrictedsecurity.ignoresunsetexpiration=" + ignoresunsetexpiration,
                "TestProperties"
        );
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(1).shouldMatch(expected);
    }

    public static void main(String[] args) {
        // Something to trigger "properties" debug output.
        try {
            for (Provider provider : Security.getProviders()) {
                System.out.println("Provider Name: " + provider.getName());
                System.out.println("Provider Version: " + provider.getVersionStr());
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
