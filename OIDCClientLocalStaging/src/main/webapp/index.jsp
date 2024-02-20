<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    <%@page import="java.util.Base64"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Index</title>
    
 <!-- CSS only -->
 <link href="UI.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">      

<style>
h4{
	display:flex;
	flex-direction:row;
	
}
h4:before,h4:after{
	content:" ";
	flex: 1 1;
	border: 1px solid white;
	margin: auto;
	text-decoration:none;
	
}


</style>
</head>
<body style="background-color: #636e72;">
<nav class="navbar navbar-expand-lg navbar-dark" style="background-color:#1e272e;">
        <div class="container-fluid">
            <a class="navbar-brand" style="color:#95ffff;font-size:20px;" href="#">e-Library (Service Integrated with <b>e-Pramaan</b>) </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarText"
                aria-controls="navbarText" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarText">
                <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="#">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Services</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Contact Us</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">About Us</a>
                    </li>
                </ul>
                <form class="d-flex">
                    <input class="form-control me-2" type="search" placeholder="Search" aria-label="Search">
                    <button type="button" class="btn btn-dark">Search</button>
                  </form>
                <!-- <span class="navbar-text">
                    Hello User
                </span> -->
            </div>
        </div>
    </nav>
<div >
  	<form class="box" method="get" action="Demo" style="margin-top: 35px;">

  <h1>e-Library Application</h1>

  <input type="text" name="" placeholder="Username">

  <input type="password" name="" placeholder="Password"> 
	
 <a href="#" > <input type="submit" name="" value="Login" disabled> </a>
 
  <h4 id="h4color" style="color: white;">OR</h4>
  
  <input type="submit"value="Login Using ePramaanNationalSSO">  

</div>

</body>
</html>
