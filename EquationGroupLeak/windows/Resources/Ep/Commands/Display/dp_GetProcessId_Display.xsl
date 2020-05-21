<?xml version='1.0' ?>
<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
 <xsl:import href="StandardTransforms.xsl"/>
 <xsl:output method="text"/>

 <xsl:template match="Process">
   <xsl:text>Process running with ID : </xsl:text>
   <xsl:value-of select="@id"/>
   <xsl:call-template name="PrintReturn"/>

   <xsl:text>      EProcess location : </xsl:text>
   <xsl:value-of select="@eprocess"/>
   <xsl:call-template name="PrintReturn"/>

 </xsl:template>

</xsl:transform>