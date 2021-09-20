package org.acme.security.jwt;

import org.eclipse.microprofile.jwt.Claims;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.smallrye.jwt.build.Jwt;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.containsString;

/**
 * Tests of the TokenSecuredResource REST endpoints
 */
@QuarkusTest
public class TokenSecuredResourceTest {

    @Test
    public void testHelloEndpoint() {
        Response response = given()
                .when()
                .get("/secured/permit-all")
                .andReturn();

        response.then()
                .statusCode(200)
                .body(containsString("hello + anonymous, isHttps: false, authScheme: null, hasJWT: false"));
    }

    @Test
    public void testHelloRolesAllowedUser() {
        Response response = given().auth()
                .oauth2(generateValidUserToken())
                .when()
                .get("/secured/roles-allowed").andReturn();

        response.then()
                .statusCode(200)
                .body(containsString(
                        "hello + jdoe@quarkus.io, isHttps: false, authScheme: Bearer, hasJWT: true, birthdate: 2001-07-13"));
    }

    @Test
    public void testHelloRolesAllowedAdmin() {
        Response response = given().auth()
                .oauth2(generateValidAdminToken())
                .when()
                .get("/secured/roles-allowed").andReturn();

        response.then()
                .statusCode(200)
                .body(containsString(
                        "hello + jdoe@quarkus.io, isHttps: false, authScheme: Bearer, hasJWT: true, birthdate: 2001-07-13"));
    }

    @Test
    public void testHelloRolesAllowedAdminOnlyWithAdminRole() {
        Response response = given().auth()
                .oauth2(generateValidAdminToken())
                .when()
                .get("/secured/roles-allowed-admin").andReturn();

        response.then()
                .statusCode(200)
                .body(containsString(
                        "hello + jdoe@quarkus.io, isHttps: false, authScheme: Bearer, hasJWT: true, birthdate: 2001-07-13"));
    }

    static String generateValidUserToken() {
        return Jwt.upn("jdoe@quarkus.io")
                .issuer("https://example.com/issuer")
                .groups("User")
                .claim(Claims.birthdate.name(), "2001-07-13")
                .sign();
    }

    static String generateValidAdminToken() {
        return Jwt.upn("jdoe@quarkus.io")
                .issuer("https://example.com/issuer")
                .groups("Admin")
                .claim(Claims.birthdate.name(), "2001-07-13")
                .sign();
    }
}
