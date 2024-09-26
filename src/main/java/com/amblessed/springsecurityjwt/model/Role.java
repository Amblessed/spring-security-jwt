package com.amblessed.springsecurityjwt.model;



/*
 * @Project Name: spring-security-jwt
 * @Author: Okechukwu Bright Onwumere
 * @Created: 26-Sep-24
 */


import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.amblessed.springsecurityjwt.model.Permission.*;



@RequiredArgsConstructor
public enum Role {
    MEMBER(Set.of(MEMBER_READ, MEMBER_CREATE)),
    ADMIN(Set.of(ADMIN_READ, ADMIN_CREATE, MEMBER_READ, MEMBER_CREATE));

    @Getter
    private final Set<Permission> permissions;


    public List<SimpleGrantedAuthority> getAuthorities() {
        var authorities = getPermissions()
                .stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getPermission()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
