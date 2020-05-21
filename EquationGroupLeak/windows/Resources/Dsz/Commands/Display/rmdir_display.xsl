<?xml version='1.0' ?>
<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

	<xsl:import href="include/StandardTransforms.xsl"/>
	
	<xsl:template match="TargetDir">
		<xsl:text>Directory removed:</xsl:text>
		<xsl:call-template name="PrintReturn"/>
		<xsl:text>    </xsl:text>
		<xsl:value-of select="."/>
		<xsl:call-template name="PrintReturn"/>
	</xsl:template>

</xsl:transform>