<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>One Time Verification</title>
</head>
<body>

<h2>One-Time Verification for User</h2>

<!-- Form to submit to OneTimePushBack -->
<form action="${pageContext.request.contextPath}/Epramaan/OneTimePushBack" method="POST">
    <!-- Display hidden form fields -->
    <input type="hidden" name="epramaanId" value="${epramaanId}" />
    <input type="hidden" name="salt" value="${salt}" />

    <!-- Fields for username and password -->
    <label for="username">Username:</label>
    <input type="text" id="username" name="username" required><br><br>

    <label for="password">Password:</label>
    <input type="password" id="password" name="password" required><br><br>

    <!-- Submit button -->
    <button type="submit">Submit</button>
</form>

</body>
</html>
