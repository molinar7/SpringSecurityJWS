package spring.security.userservice.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.userservice.domain.AppUser;

public interface AppUserRepo extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
