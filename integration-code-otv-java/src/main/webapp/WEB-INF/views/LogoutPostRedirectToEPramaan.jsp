<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Logging Out...</title>
<script type="text/javascript">
	// Auto-submit the form when the page is loaded
	window.onload = function() {
		document.getElementById("logoutForm").submit();
	};
</script>
</head>
<body>
	<h2>Logging out...</h2>
	<form id="logoutForm" action="<%=request.getAttribute("logoutUrl")%>" method="POST">
		<textarea hidden name="data"><%=request.getAttribute("data")%></textarea>	<!-- name must be "data" -->
	</form>
</body>
</html>
