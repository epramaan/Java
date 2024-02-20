import java.sql.SQLException;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.sql.DataSource;

public class MyServletContextListener implements ServletContextListener{

	@Override
	public void contextDestroyed(ServletContextEvent arg0) {
		System.out.println("Inside contextDestroyed method");
		DataSource dataSource = MvcConfiguration.getDataSource();
		try {
			System.out.println("Inside try block while closing dataSource");
			dataSource.getConnection().close();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		
	}

	@Override
	public void contextInitialized(ServletContextEvent arg0) {
		System.out.println("Inside contextInitialized method");
		
	}
}
