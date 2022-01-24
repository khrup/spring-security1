package com.cos.security1.oauth;

import com.cos.security1.Model.User;
import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    //구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("getClientRegistration = {}",  userRequest.getClientRegistration()); //registrationId로 어떤 OAuth로 로그인했는지 확인가능.
        log.info("getAccessToken = {}",  userRequest.getAccessToken().getTokenValue());
        log.info("getAdditionalParameters = {}",  userRequest.getAdditionalParameters());

        OAuth2User oauth2User = super.loadUser(userRequest);
        //구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 -> code를 리턴(OAuth-Client 라이브러리) -> AccessToken 요청
        //userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원 프로필을 받아준다.
        log.info("getAttributes = {}",  oauth2User.getAttributes());

        //회원가입 강제로 진행
        String provider = userRequest.getClientRegistration().getClientId(); //google
        String providerId = oauth2User.getAttribute("sub");
        String username = provider + "_" + providerId; //google_1098125718437
        String password = bCryptPasswordEncoder.encode("1234");
        String email = oauth2User.getAttribute("email");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        if(userEntity == null) {
            log.info("회원가입을 진행합니다.");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }else{
            log.info("구글 로그인을 진행합니다.");
        }

        return new PrincipalDetails(userEntity, oauth2User.getAttributes());
    }
}
