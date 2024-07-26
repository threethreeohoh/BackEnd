package threethreeohoh.rainfall.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import threethreeohoh.rainfall.jwt.JWTFilter;
import threethreeohoh.rainfall.jwt.JWTUtil;
import threethreeohoh.rainfall.jwt.LoginFilter;

import java.util.Collection;
import java.util.Collections;

@Configuration // 이 클래스가 Spring의 설정 클래스임을 나타냄. 즉, Spring 컨테이너에서 이 클래스를 설정 정보로 사용
@EnableWebSecurity // 이 어노테이션을 통해 Spring Security의 웹 보안 지원을 활성화.
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;

    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    @Bean // AuthenticationManager Bean 등록
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }


    // 특정 HTTP 요청에 대한 웹 기반 보안 구성 (인증/인가 및 로그아웃을 설정)
    @Bean // 이 메서드가 반환하는 객체를 Spring 컨테이너가 관리하는 빈(Bean)으로 등록함
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception { //SecurityFilterChain: Spring Security의 필터 체인을 구성합니다, HttpSecurity: 웹 기반 보안을 설정하는 데 사용됩니다

        // 로그인 필터 관련 CORS 설정
        httpSecurity
                .cors((cors) -> cors.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("*")); // 프론트엔드의 3000번대 포트 허용
                        configuration.setAllowedMethods(Collections.singletonList("*")); // 허용할 메서드 (GET, POST, PUT 등등) : 전부 허용
                        configuration.setAllowCredentials(true); //
                        configuration.setAllowedHeaders(Collections.singletonList("*")); // 허용할 헤더
                        configuration.setMaxAge(3600L); // 허용 가능 시간

                        configuration.setExposedHeaders(Collections.singletonList("Authorization")); // 서버에서 클라이언트로 헤더를 전송할때 Authorization에 jwt를 넣어서 보내줄 것이기 때문에 Authorization 헤더도 허용해줘야함

                        return configuration;
                    }
                }));

        httpSecurity
                .csrf(AbstractHttpConfigurer::disable);// CSRF 보호 기능을 비활성화, csrf(Cross site Request forgery) : 공격자가 인증된 브라우저에 저장된 쿠키의 세션 정보를 활용하여 웹 서버에 사용자가 의도하지 않은 요청을 전달하는 것.(즉, 정상적인 사용자가 의도치 않은 위조요청을 보내는 것을 의미)
        //  REST API이므로 basic auth 및 csrf 보안을 사용하지 않음 (저는 REST API를 이용한 개발을 진행 할 예정입니다.Rest Api 환경에서는 Session 기반 인증과 다르기 때문에 서버에 인증정보를 보관하지 않고, 권한 요청시 필요한 인증정보(OAuth2, Jwt토큰 등)요청을 포함하기 때문에 굳이 불필요한 csrf 보안을 활성화할 필요가 없습니다.)
        // 따라서 csrf는 disable 처리 하였습니다.
        httpSecurity
                .httpBasic(AbstractHttpConfigurer::disable); // HTTP Basic 인증을 비활성화
        // Json을 통해 로그인을 진행하는데, 로그인 이후 refresh 토큰이 만료되기 전까지 토큰을 통한 인증을 진행할것 이기 때문에 HTTP Basic 인증을 비활성화 하였습니다.
        httpSecurity
                .formLogin(AbstractHttpConfigurer::disable); // 폼 로그인 기능을 비활성화
        // 인가 작업
        httpSecurity
                .authorizeHttpRequests((authorize) -> authorize // 특정 HTTP 요청에 대한 접근 권한을 설정 (인증, 인가가 필요한 URL 지정)
                        .requestMatchers("/login", "/", "/join").permitAll() // 해당 API에 대해서는 모든 요청을 허가 (이 경로들은 누구나 접근할 수 있도록 허용)
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()); // 나머지의 모든 요청은 인증된 사용자만 접근 가능하도록 설정
        httpSecurity
                .logout((logout) -> logout.logoutSuccessUrl("/login") // 로그아웃 설정 구성 , 로그아웃 성공 후 이동할 URL("/login")을 설정
                        .invalidateHttpSession(true)); // 로그아웃 시 세션을 무효화 (로그아웃 이후 전체 세션 삭제 여부)
        // *중요* JWT 방식에서는 항상 세션을 Stateless 방식으로 관리
        httpSecurity
                .sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // 세션 관리 정책 설정(세션 생성 및 사용여부에 대한 정책 설정), 세션을 사용하지 않도록 설정(주로 JWT 또는 다른 토근 기반 인증 방식에서 사용됨)
                //SessionCreationPolicy() : 정책을 설정합니다.
                //SessionCreationPolicy.Stateless : 4가지 정책 중 하나로, 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않습니다. (JWT와 같이 세션을 사용하지 않는 경우에 사용합니다)
        // jwt 토큰을 검증하는 필터 등록
        httpSecurity
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
        // 로그인을 검증하는 필터 등록
        httpSecurity
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class); // UsernamePasswordAuthenticationFilter 를 딱 대체하는 필터를 만든 것이기 때문에 Before나 After이 아닌 At으로 설정

        return httpSecurity.build();
    }

    @Bean
    public static BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder(); // DelegatingPasswordEncoder : 여러 인코딩 알고리즘을 사용할 수 있게 해주는 기능
    }

    /* // BCryptPasswordEncoder 알고리즘이 아닌 더 좋은 비밀번호 암호화 알고리즘으로 변경 -> PasswordEncoder
    @Bean // 이 메서드가 반환하는 'BCryptPasswordEncoder' 객체를 Spring 컨테이너가 관리하는 빈으로 등록
    public BCryptPasswordEncoder bCryptPasswordEncoder() { // 스프링 시큐리티에서 제공하며 bcrypt 해싱 함수로 암호를 인코딩하는 BCryptPasswordEncoder를 직접 불러서 사용하였습니다.
        return new BCryptPasswordEncoder(); // BCryptPasswordEncoder: 비밀번호를 암호화하는 데 사용되는 암호화 도구입니다. Spring Security에서 비밀번호를 안전하게 저장하고 검증하는 데 사용됩니다.
    }
    */

}
