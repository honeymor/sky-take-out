package com.sky.interceptor;


import com.sky.constant.JwtClaimsConstant;
import com.sky.context.BaseContext;
import com.sky.properties.JwtProperties;
import com.sky.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
@Slf4j
public class JwtTokenUserInterceptor implements HandlerInterceptor {

    @Autowired
    private JwtProperties jwtProperties;

    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if(!(handler instanceof HandlerMethod)){
            return true;
        }
        String token = request.getHeader(jwtProperties.getUserTokenName());
        try {
            log.info("jwt检验：{}", token);
            Claims claim= JwtUtil.parseJWT(jwtProperties.getUserSecretKey(), token);

            Long userId = Long.valueOf(claim.get(JwtClaimsConstant.USER_ID).toString());
            log.info("当前用户的id:{}", userId);
            BaseContext.setCurrentId(userId);
            return true;
        }catch (Exception ex){
            response.setStatus(401);
            return false;
        }
    }

}
