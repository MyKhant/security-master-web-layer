package com.example.securitymaster.security;

public interface SecurityRoles {
    String ROLES_PREFIX = "ROLE_";

    String ROLES_ADMIN = "SUPER_ADMIN";

    String CUSTOMERS_ADMIN ="CUSTOMERS_ADMIN";
    String CUSTOMERS_READ = "CUSTOMERS_READ";
    String CUSTOMERS_CREATE = "CUSTOMERS_CREATE";
    String CUSTOMERS_DELETE = "CUSTOMERS_DELETE";
    String CUSTOMERS_PAG_VIEW = "CUSTOMERS_PAG_VIEW";

    String DEPARTMENTS_ADMIN = "DEPARTMENTS_ADMIN";
    String DEPARTMENTS_READ = "DEPARTMENTS_READ";
    String DEPARTMENTS_CREATE = "DEPARTMENTS_CREATE";
    String DEPARTMENTS_DELETE = "DEPARTMENTS_DELETE";
    String DEPARTMENTS_PAG_VIEW = "DEPARTMENTS_PAG_VIEW";


    String EMPLOYEES_ADMIN = "EMPLOYEES_ADMIN";
    String EMPLOYEES_READ = "EMPLOYEES_READ";
    String EMPLOYEES_CREATE = "EMPLOYEES_CREATE";
    String EMPLOYEES_DELETE = "EMPLOYEES_DELETE";
    String EMPLOYEES_PAG_VIEW = "EMPLOYEES_PAG_VIEW";


}
