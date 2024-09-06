package com.ohgiraffers.jwt.auth.handler;

import com.ohgiraffers.jwt.auth.service.CustomUserDetailService;
import com.ohgiraffers.jwt.auth.service.CustomUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


/*
* authenticationProvider
*
* 커스텀 인증제공자
* 사용자가 입력한 사용자 이름과 비밀번호를 테이터 베이스 정보와 비교하여 사용자 자격을 증명
*
* */
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private CustomUserDetailService detailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        //로그인 요청 정보를 가지고 있는 token
        UsernamePasswordAuthenticationToken loginToken = (UsernamePasswordAuthenticationToken) authentication;

        //사용자가 입력한 id
        String memberId = loginToken.getName();

        //사용자가 입력한password
        String password = (String) loginToken.getCredentials();

        //사용자가 입력한 id로 찾아온 customuserDetail
        //customuserdetailservice의 loaduserByUsername메소드로 찾아올수있다
        CustomUserDetails member = (CustomUserDetails) detailsService.loadUserByUsername(memberId);

        //passwordEncoder의 matches메소드로 사용자가 입력한 password와 db에서 찾아온 password가 일치하는지 확인한다.(복호화 진행)
        //암호화된 비밀번호를 해독해서 일치하는지 확인 (복호회)
        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new BadCredentialsException(password + "는 비밀번호가 아닙니다.");
        }
        return new UsernamePasswordAuthenticationToken(member, password, member.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
