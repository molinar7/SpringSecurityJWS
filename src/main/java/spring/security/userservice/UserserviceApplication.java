package spring.security.userservice;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import spring.security.userservice.domain.AppUser;
import spring.security.userservice.domain.Role;
import spring.security.userservice.service.AppUserService;

import java.util.ArrayList;

@SpringBootApplication
public class UserserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserserviceApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder () {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(AppUserService appUserService) { // this runs after the Spring initialise
		return args -> {
			appUserService.saveRole(new Role(null, "ROLE_USER"));
			appUserService.saveRole(new Role(null, "ROLE_MANAGER"));
			appUserService.saveRole(new Role(null, "ROLE_ADMIN"));
			appUserService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));


			appUserService.saveAppUser(new AppUser(null, "Mario", "Molinar7", "1234", new ArrayList<>()));
			appUserService.saveAppUser(new AppUser(null, "Juan", "jhony", "1234", new ArrayList<>()));
			appUserService.saveAppUser(new AppUser(null, "Pedro", "peter", "1234", new ArrayList<>()));
			appUserService.saveAppUser(new AppUser(null, "Alejandra", "alefu", "1234", new ArrayList<>()));

			appUserService.addRoleToAppUser("Molinar7", "ROLE_USER");
			appUserService.addRoleToAppUser("jhony", "ROLE_USER");
			appUserService.addRoleToAppUser("peter", "ROLE_USER");
			appUserService.addRoleToAppUser("alefu", "ROLE_USER");

			appUserService.addRoleToAppUser("Molinar7", "ROLE_MANAGER");
			appUserService.addRoleToAppUser("jhony", "ROLE_MANAGER");
			appUserService.addRoleToAppUser("peter", "ROLE_MANAGER");

			appUserService.addRoleToAppUser("Molinar7", "ROLE_SUPER_ADMIN");
			appUserService.addRoleToAppUser("alefu", "ROLE_SUPER_ADMIN");


		};
	}

}
