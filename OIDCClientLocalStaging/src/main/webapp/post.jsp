<%@ page import="java.lang.String" %>
<%--   <%@taglib uri="http://www.springframework.org/tags" prefix="spring"%> --%>

<script>

window.onload = function(){
	  document.forms['ResponsePost'].submit()

	}
</script>

 <%
   String acsUrl = (String) request.getAttribute("redirectionURL");
  %>

<form autocomplete="off" action=<%=acsUrl%> method="post" name='ResponsePost'>

</form> 