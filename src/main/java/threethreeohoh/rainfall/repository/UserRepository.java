package threethreeohoh.rainfall.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import threethreeohoh.rainfall.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    Boolean existsByUsername(String username);

    UserEntity findByUsername(String username);
}
