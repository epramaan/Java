
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import javax.sql.DataSource;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

public class DDemo {
	
	private static DataSource dataSource = MvcConfiguration.getDataSource();
	
	private static JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
	


	public void insertNewRecord(String codeVerifier, String nonce, String stateId) {
		System.out.println("Inside insertNewRecord method");
		String sql = "INSERT INTO oidc_integration (code_verifier, nonce, stateId, timestamp)"
                + " VALUES (?, ?, ?, now())";
    jdbcTemplate.update(sql, codeVerifier, nonce, stateId);
	}
	
	
	public List<MDemo> fetchRecord(String stateId) {
		System.out.println("Inside fetchRecord method");
		String sql = "SELECT * FROM oidc_integration WHERE stateId='"+stateId+"'";
		List<MDemo> myModelData = jdbcTemplate.query(sql, new RowMapper<MDemo>() {
			
		@Override
        public MDemo mapRow(ResultSet rs, int rowNum) throws SQLException {
			MDemo myModel = new MDemo();
			myModel.setCodeVerifier(rs.getString("code_verifier"));
			myModel.setNonce(rs.getString("nonce"));
			return myModel;
            }
 });
		return myModelData;
	}	        
}
