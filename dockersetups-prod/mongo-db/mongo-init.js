db.createUser(
    {
        user: "gsp",
        pwd: "rootpass",
        roles: [
            {
                role: "readWrite",
                db: "exl"
            }
        ]
    }
);
db.createCollection("templates");
db.createCollection("reports");
db.createCollection("users");