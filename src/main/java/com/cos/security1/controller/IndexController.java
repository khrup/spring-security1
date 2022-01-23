package com.cos.security1.controller;

import com.cos.security1.Model.User;
import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
@RequiredArgsConstructor
public class IndexController {

    final UserRepository userRepository;
    final BCryptPasswordEncoder bCryptPasswordEncoder;

    //@AuthenticationPrincipal 세션정보 확인가능
    @GetMapping("/test/login")
    @ResponseBody
    public String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails){
        log.info("/test/login =========");
        //첫번째 user 세션정보 가져오기
        PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
        log.info("authentication : " + principalDetails.getUser());
        //@AuthenticationPrincipal를 이용해서 user 세션정보 가져오기
        log.info("userDetails = {}", userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String testOAuthLogin(Authentication authentication, @AuthenticationPrincipal OAuth2User oauth){
        log.info("/test/oauth/login =========");
        OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
        log.info("authentication = {}" , oAuth2User.getAttributes());
        log.info("oauth2User = {} ", oauth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    //localhost:8080/
    //localhost:8080
    @GetMapping({"/", ""})
    public String index(){
        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    public String user(){
        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager(){
        return "manager";
    }

    @GetMapping("/login")
    @ResponseBody
    public String login(){
        return "login";
    }

    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user){
        log.info("user = {}", user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);

        userRepository.save(user); //회원가입 잘됨.비밀번호 : 1234 => 시큐리티 로그인을 할 수 없음... 이유는 패스워드가 암호화가 안되었기 때문에!!!
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    @ResponseBody
    public String info(){
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    @ResponseBody
    public String data(){
        return "개인정보";
    }
}
