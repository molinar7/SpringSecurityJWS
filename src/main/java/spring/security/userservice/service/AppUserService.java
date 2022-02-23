package spring.security.userservice.service;

import spring.security.userservice.domain.AppUser;
import spring.security.userservice.domain.Role;

import java.util.List;

public interface AppUserService {
    AppUser saveAppUser (AppUser appUser);
    Role saveRole(Role role);
    void addRoleToAppUser(String username, String roleName);// username must be unique in the DB
    AppUser getUser(String username);// username must be unique in the DB
    List<AppUser> getAppUsers();// in real world you should return pages and not all the data

}
