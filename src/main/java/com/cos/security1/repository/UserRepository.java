package com.cos.security1.repository;

import com.cos.security1.Model.User;
import org.springframework.data.jpa.repository.JpaRepository;

//CRUD 함수를 JpaRepository가 들고있음.
//@Repository라는 어노테이션이 없어도 IoC가 된다. 이유는 JpaRepository를 상속했기 때문이다.
public interface UserRepository extends JpaRepository<User, Integer> {

    //findBy규칙 -> Username문법
    //select * from user where username = ? 호출됨
    public User findByUsername(String username); //jpa query method

    //select * from user where email = ?
    public User findByEmail(String email);
}
