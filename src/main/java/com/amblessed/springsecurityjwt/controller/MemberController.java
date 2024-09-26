package com.amblessed.springsecurityjwt.controller;



/*
 * @Project Name: spring-security-jwt
 * @Author: Okechukwu Bright Onwumere
 * @Created: 26-Sep-24
 */


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/management")
public class MemberController {

    @GetMapping
    public String getMember() {
        return "Secured Endpoint :: GET - Member Controller";
    }

    @PostMapping
    public String post() {
        return "POST :: management controller";
    }
}
