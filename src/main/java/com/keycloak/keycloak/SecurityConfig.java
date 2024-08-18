package com.keycloak.keycloak;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
  private final JwtAuthConverter jwtAuthConverter ;
  @Bean
  public SecurityFilterChain secuirtyFilterChain(HttpSecurity http) throws Exception {
  /* // http //.csrf().disable().authorizeHttpRequests()
    //  .anyRequest().authenticated();
    http.authorizeHttpRequests(auth
        ->auth.anyRequest().authenticated()
    );
    http.oauth2ResourceServer(oauth2 -> oauth2
      .jwt(withDefaults()));
    http.sessionManagement(session
      -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));*/

    http
      .csrf().disable()
      .authorizeHttpRequests()
        .anyRequest().authenticated();

    http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthConverter);

    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    return http.build();
  }

  @Bean
  public JwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
    return JwtDecoders.fromIssuerLocation(properties.getJwt().getIssuerUri());
  }
}
