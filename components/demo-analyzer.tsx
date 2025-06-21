import { Box, Typography, Container, Paper } from "@mui/material"

const DemoAnalyzer = () => {
  return (
    <Container maxWidth="md">
      <Paper elevation={3} sx={{ padding: 3, marginTop: 4, marginBottom: 4 }}>
        <Box textAlign="center" mb={3}>
          <Typography variant="h4" fontWeight="bold" color="primary">
            🛡️ Phishing Detection
          </Typography>
          <Typography variant="subtitle1" color="textSecondary">
            Analyze and detect potential phishing attempts.
          </Typography>
        </Box>

        <Box mb={3}>
          <Typography variant="h6" fontWeight="bold">
            How it Works:
          </Typography>
          <Typography variant="body1">
            This is a demo analyzer. In a real application, you would paste or upload content (e.g., email body, URL)
            for analysis. The system would then use various techniques (e.g., URL analysis, content analysis, sender
            reputation) to determine the likelihood of it being a phishing attempt.
          </Typography>
        </Box>

        <Box mb={3}>
          <Typography variant="h6" fontWeight="bold">
            Example Analysis:
          </Typography>
          <Typography variant="body1">
            Imagine you paste an email with a suspicious link. The analyzer might check the link against known phishing
            databases, analyze the email content for urgent requests or grammatical errors, and verify the sender's
            authenticity.
          </Typography>
        </Box>

        <Box mt={4} textAlign="center">
          <Typography variant="body2" color="textSecondary">
            Powered by Phishing Detection
          </Typography>
        </Box>
      </Paper>
    </Container>
  )
}

export default DemoAnalyzer
