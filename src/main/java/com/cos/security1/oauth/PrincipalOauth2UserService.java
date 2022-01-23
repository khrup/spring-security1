package com.cos.security1.oauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    //구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("getClientRegistration = {}",  userRequest.getClientRegistration()); //registrationId로 어떤 OAuth로 로그인했는지 확인가능.
        log.info("getAccessToken = {}",  userRequest.getAccessToken().getTokenValue());
        log.info("getAdditionalParameters = {}",  userRequest.getAdditionalParameters());
        //구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 -> code를 리턴(OAuth-Client 라이브러리) -> AccessToken 요청
        //userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원 프로필을 받아준다.
        log.info("getAttributes = {}",  super.loadUser(userRequest).getAttributes());


        OAuth2User oauth2User = super.loadUser(userRequest);
        //회원가입 강제로 진행해볼 예정
        return super.loadUser(userRequest);
    }
}
