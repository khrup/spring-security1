package com.cos.security1.config;

import com.cos.security1.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록이 됩니다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)//securedEnavled : secured 어노테이션 활성화, prePostEnabled : PreAuthorize, PostAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    PrincipalOauth2UserService principalOauth2UserService;

    //해당 메소드의 리턴되는 오브젝트는 Bean Container에 등록된다.
    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() //이 주소로 들어오면 인증이 필요
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")//해당 권한이 있는 사람만 접근가능
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')") //해당 권한이 있는 사람만 접근가능
                .anyRequest().permitAll() //어떤 요청이든 허가
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") //login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해준다.
                .defaultSuccessUrl("/") //로그인 이후 호출 url
                .and()
                .oauth2Login()
                .loginPage("/loginForm") //구글 로그인이 완료된 뒤의 후처리가 필요함. Tip.코드X, (액세스 토큰+사용자프로필정보 O)
                .userInfoEndpoint()
                .userService(principalOauth2UserService)
                ;
        //1.코드받기(인증), 2.액세스토큰(권한), 3.사용자프로필 정보를 가져오고 4.그 정보를 토대로 회원가입을 자동으로 진행시키기도함
        //5. (이메일, 전화번호, 이름, 아이디), 쇼핑몰 -> (집주소), 백화점몰 -> (vip 등급, 일반등급)
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());//정적 소스들은 무시해준다.
    }
}
