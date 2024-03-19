<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    
    <%@page import="com.google.gson.Gson"%>
    <%@page import="java.lang.reflect.Type"%>
    <%@page import="com.google.gson.reflect.TypeToken"%>
    <%@page import="java.util.Map"%>
<!DOCTYPE html>
<html>
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
<head>
<meta charset="ISO-8859-1">
<title>Claimset</title>
</head>
<body style="background-color: #636e72;">
<div><nav class="navbar navbar-expand-lg navbar-dark" style="background-color:#1e272e;">
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
                    <li class="nav-item">
                        <a class="nav-link" href="/Logout">Logout</a>
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
<div class="row">
		<div style="width:50%;margin: auto;">
		
			
			<div class="panel panel-default" style="box-shadow: 0 4px 10px 4px rgba(19, 35, 47, .3);background-color:#FFF;  border-radius: 4px;margin-top:20px">
				<%
						Map<String,Object> tokenClaims = (Map<String,Object>)request.getAttribute("JWSClaimset");
						String name = (String)tokenClaims.get("given_name");
						
						if(name == null){
							name = (String)tokenClaims.get("name");
						}else{
							name = name.split(" ")[0];
						}
						//tokenClaims.remove("dob");
						//tokenClaims.remove("birthdate");
						//tokenClaims.remove("preferred_username");
						//tokenClaims.remove("email");
						//tokenClaims.remove("mobile_number");
						//tokenClaims.remove("masked_aadhaar");
						//tokenClaims.remove("phone_number");
						//tokenClaims.put("given_name",name);
						%>
				
        <div class="top-row">
            <h2 style="text-align: center;color: blue; font-size: 25px; padding-top:5px; "> Welcome <%=name%>&nbsp;
                <hr style="color: grey;border-radius: 5px;box-shadow: 12px;">
            </h2>
        </div>	
				
				<div class="panel-body" style="padding:0px;">				
						
						<%
						for(String key:tokenClaims.keySet()){
						%>
						
						<div class="row g-0" style="padding-top:5px; padding-bottom:5px; border-bottom: 1px solid #eee">
						<div style="width:40%;display:inline-block;padding-left:10px">
						<strong><%=key.toUpperCase() %> </strong>
						</div>
						<div style="width:60%;display:inline-block;padding-left:25px">
						<%=tokenClaims.get(key) %>
						</div> 
						</div>
						<%} %>
						<div class="row g-0" style="padding-top:5px; padding-bottom:5px; border-bottom: 1px solid #eee">
						<div style="width:30%;display:inline-block;vertical-align:top;padding-left:10px">
						<strong>JWT Token </strong>
						</div>
						<div style="width:60%;display:inline-block;padding-left:25px">
						<textarea style="width:100%;height:75px;"  ><%=request.getAttribute("JWSClaimset") %></textarea>
						<textarea style="width:100%;height:75px;"  ><%=request.getAttribute("tokenRequestParameters") %></textarea>
						
						</div> 
						</div>
					</div>
					</div>
					</div>
					</div>	
						
			

<h3 style="color:white;word-wrap:break-word;"></h3>

</div>
</body>
</html>