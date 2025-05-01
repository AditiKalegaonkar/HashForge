# HashForge
Custom hashing algorithm made by modifing bcrypt and SHA256

### How actually the parameter are hashed?

In this project, I implemented the **SHA-256** algorithm and the bcrypt algorithm from scratch. Typically, companies use fixed salt and cost parameters, which can make it easier for intruders to predict passwords. However, with HashForge, users can choose the cost and salt length themselves. These parameters are cleverly concealed within the hash.


The process begins by hashing the password using the user-defined salt length and cost (the number of times the password is hashed using SHA256). **In the encoding function, these parameters are hidden by appending them to the end of the string, which is then right-rotated based on the password length.**


**During decoding, the user-defined password length is used to extract the salt and cost from the stored hash. The password is then rehashed to verify the credentials.**

The unique aspect of this method is that the **salt and cost are converted into corresponding Base64 characters, allowing them to be represented by a single character,** which simplifies the decoding process.

~~~sh
Entered the password: Summer2025
Entered salt length: 8
Entered cost: 12
Bcrypt Hash: 54f2fca2bIc7d6dbd8312661d9726bb783515f179d74405000b8839efb149e4d8M
                     \_/                                                     \_/
                     salt                                                    cost
~~~

**I** represents character for salt_length and **M** cost represents character for cost.

One limitation of this project is that the salt and cost values can only range from 0 to 63.

Feel free to give it a try, and your suggestions are always welcome!
