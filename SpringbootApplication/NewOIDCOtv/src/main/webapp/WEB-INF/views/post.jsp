<%@ page import="java.lang.String" %>
<%--   <%@taglib uri="http://www.springframework.org/tags" prefix="spring"%> --%>

<script>

window.onload = function(){
	  document.forms['ResponsePost'].submit()

	}
</script>

<!-- <body onload="document.forms[0].submit()"> -->
 <%
   String acsUrl = (String) request.getAttribute("redirectionURL");
  %>

<form autocomplete="off" action=<%=acsUrl%> method="post" name='ResponsePost'>

<div>

<%-- <input type="hidden" name="token" value="<%= request.getAttribute("token") %>" autocomplete="off"/>--%>
<textarea id="data" hidden name="data" ><%= request.getAttribute("data") %></textarea>
<%-- <input type="hidden" name="key" value="<%= request.getAttribute("key") %>" autocomplete="off"/> --%>

</div>
</form> 