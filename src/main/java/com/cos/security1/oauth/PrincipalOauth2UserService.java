package com.cos.security1.oauth;

import com.cos.security1.Model.User;
import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.oauth.provider.FaceBookUserInfo;
import com.cos.security1.oauth.provider.GoogleUserInfo;
import com.cos.security1.oauth.provider.NaverUserInfo;
import com.cos.security1.oauth.provider.OAuth2UserInfo;
import com.cos.security1.repository.UserRepository;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

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
        OAuth2UserInfo oAuth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
            log.info("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
            log.info("페이스북 로그인 요청");
            oAuth2UserInfo = new FaceBookUserInfo(oauth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            log.info("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>)oauth2User.getAttributes().get("response"));
        }else{
            log.info("우리는 구글과 페이스북, 네이버만 지원해요 ㅎㅎㅎ");
        }

        String provider = oAuth2UserInfo.getProvider();//userRequest.getClientRegistration().getClientId(); //google
        String providerId = oAuth2UserInfo.getProviderId();//oauth2User.getAttribute("sub");
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
