package com.example;

import org.springframework.stereotype.Component;

@Component
public class SqlSolver {

  // PostgreSQL final query for Question 1 (odd regNo)
  private static final String POSTGRES_Q1 = "WITH eligible AS (\n" +
      "  SELECT\n" +
      "    p.amount            AS salary,\n" +
      "    e.first_name,\n" +
      "    e.last_name,\n" +
      "    e.dob,\n" +
      "    d.department_name,\n" +
      "    p.payment_time,\n" +
      "    e.emp_id\n" +
      "  FROM payments p\n" +
      "  JOIN employee  e ON e.emp_id = p.emp_id\n" +
      "  JOIN department d ON d.department_id = e.department\n" +
      "  WHERE EXTRACT(DAY FROM p.payment_time) <> 1\n" +
      "),\n" +
      "max_sal AS (\n" +
      "  SELECT MAX(salary) AS max_salary FROM eligible\n" +
      ")\n" +
      "SELECT\n" +
      "  e.salary                             AS \"SALARY\",\n" +
      "  (e.first_name || ' ' || e.last_name) AS \"NAME\",\n" +
      "  EXTRACT(YEAR FROM AGE(e.payment_time::date, e.dob))::int AS \"AGE\",\n" +
      "  e.department_name                    AS \"DEPARTMENT_NAME\"\n" +
      "FROM eligible e\n" +
      "JOIN max_sal m ON e.salary = m.max_salary\n" +
      "ORDER BY e.emp_id\n" +
      "LIMIT 1;";

  public String solve(int lastTwoDigits) {
    boolean isOdd = (lastTwoDigits % 2) == 1;
    if (isOdd) {
      return POSTGRES_Q1;
    } else {
      throw new IllegalStateException("Even regNo → Question 2 not implemented.");
    }
  }
}
